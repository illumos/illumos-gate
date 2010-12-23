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
 * Copyright 2009 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>
#include <libgen.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <boot_http.h>
#include <errno.h>
#include <ctype.h>
#include <openssl/pkcs7.h>
#include <openssl/ocsp.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include "pkglib.h"
#include "pkglibmsgs.h"
#include "pkglocale.h"
#include "keystore.h"
#include "pkgweb.h"
#include "pkgerr.h"
#include "p12lib.h"

/* fixed format when making an OCSP request */
#define	OCSP_REQUEST_FORMAT \
	"POST %s HTTP/1.0\r\n" \
	"Content-Type: application/ocsp-request\r\n" \
	"Content-Length: %d\r\n\r\n"

/*
 * no security is afforded by using this phrase to "encrypt" CA certificates,
 * but it might aid in debugging and has to be non-null
 */
#define	WEB_CA_PHRASE		"schizophrenic"

/* This one needs the ': ' at the end */
#define	CONTENT_TYPE_HDR	"Content-Type"
#define	CONTENT_DISPOSITION_HDR	"Content-Disposition"
#define	CONTENT_OCSP_RESP	"application/ocsp-response"
#define	CONTENT_LENGTH_HDR	"Content-Length"
#define	LAST_MODIFIED_HDR	"Last-Modified"
#define	OCSP_BUFSIZ	1024

/*
 * default amount of time that is allowed for error when checking
 * OCSP response validity.
 * For example, if this is set to 5 minutes, then if a response
 * is issued that is valid from 12:00 to 1:00, then we will
 * accept it if the local time is between 11:55 and 1:05.
 * This takes care of not-quite-synchronized server and client clocks.
 */
#define	OCSP_VALIDITY_PERIOD	(5 * 60)

/* this value is defined by getpassphrase(3c) manpage */
#define	MAX_PHRASELEN		257

/* Max length of "enter password again" prompt message */
#define	MAX_VERIFY_MSGLEN	1024

/* local prototypes */
static boolean_t remove_dwnld_file(char *);
static boolean_t get_ENV_proxyport(PKG_ERR *, ushort_t *);
static boolean_t make_link(char *, char *);
static WebStatus web_send_request(PKG_ERR *, int, int, int);
static boolean_t web_eval_headers(PKG_ERR *);
static WebStatus web_get_file(PKG_ERR *, char *, int, char **);
static boolean_t ck_dwnld_dir_space(PKG_ERR *, char *, ulong_t);
static WebStatus web_connect(PKG_ERR *);
static boolean_t web_setup(PKG_ERR *);
static boolean_t check_dwnld_dir(PKG_ERR *, char *);
static boolean_t parse_url_proxy(PKG_ERR *, char *, char *, ushort_t);
static boolean_t web_disconnect(void);
static char *get_unique_filename(char *, char *);
static boolean_t get_ENV_proxy(PKG_ERR *, char **);
static char *condense_lastmodified(char *);
static int web_verify(int, X509_STORE_CTX *);
static int get_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
static boolean_t get_ocsp_uri(X509 *, char **);
static OCSPStatus ocsp_verify(PKG_ERR *, X509 *, X509 *, char *, url_hport_t *,
    STACK_OF(X509) *);
static char	*get_time_string(ASN1_GENERALIZEDTIME *);
static char	*write_ca_file(PKG_ERR *, char *, STACK_OF(X509) *, char *);
static boolean_t _get_random_info(void *, int);
static boolean_t	init_session(void);
static void	progress_setup(int, ulong_t);
static void	progress_report(int, ulong_t);
static void	progress_finish(int);
static char	*replace_token(char *, char, char);
static void	dequote(char *);
static void	trim(char *);


/*
 * structure used to hold data passed back to the
 * X509 verify callback routine in validate_signature()
 */
typedef struct {
	url_hport_t	*proxy;
	PKG_ERR		*err;
	STACK_OF(X509)	*cas;
} verify_cb_data_t;

/* Progress bar variables */
static ulong_t const_increment, const_divider, completed, const_completed;

/* current network backoff wait period */
static int cur_backoff = 0;

/* download session context handle */
static WEB_SESSION *ps;

static int	webpkg_install = 0;
static char	*prompt = NULL;
static char	*passarg = NULL;


/* ~~~~~~~~~~~~~~ Public Functions ~~~~~~~~~~~~~~~~~~~ */

/*
 * Name:		set_prompt
 * Description:	Specifies the prompt to use with the pkglib
 *		passphrase callback routine.
 *
 * Arguments:	newprompt - The prompt to display
 *
 * Returns :	NONE
 */
void
set_passphrase_prompt(char *newprompt)
{
	prompt = newprompt;
}

/*
 * Name:		set_passarg
 * Description:	Specifies the passphrase retrieval method
 *		 to use with the pkglib
 *		passphrase callback routine.
 *
 * Arguments:	newpassarg - The new password retrieval arg
 *
 * Returns :	NONE
 */
void
set_passphrase_passarg(char *newpassarg)
{
	passarg = newpassarg;
}

/*
 * Name:		get_proxy_port
 * Description:	Resolves proxy specification
 *
 * Arguments:	err - where to record any errors.
 *     		proxy - Location to store result - if *proxy is not
 *		null, then it will be validated, but not changed
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise
 *		on success, *proxy and *port are set to either
 *		the user-supplied proxy and port, or the
 *		ones found in the environment variables
 *		HTTPPROXY and/or HTTPROXYPORT
 */
boolean_t
get_proxy_port(PKG_ERR *err, char **proxy, ushort_t *port)
{
	if (*proxy != NULL) {
		if (!path_valid(*proxy)) {
			/* bad proxy supplied */
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_BAD_PROXY), *proxy);
			return (B_FALSE);
		}
		if (!get_ENV_proxyport(err, port)) {
			/* env set, but bad */
			return (B_FALSE);
		}
	} else {
		if (!get_ENV_proxy(err, proxy)) {
			/* environment variable set, but bad */
			return (B_FALSE);
		}
		if ((*proxy != NULL) && !path_valid(*proxy)) {
			/* env variable set, but bad */
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_BAD_PROXY), *proxy);
			return (B_FALSE);
		}
		if (!get_ENV_proxyport(err, port)) {
			/* env variable set, but bad */
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

/*
 * Name:		path_valid
 * Description:	Checks a string for being a valid path
 *
 * Arguments:	path - path to validate
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise.
 *		B_FALSE means path was null, too long (>PATH_MAX),
 *		or too short (<1)
 */
boolean_t
path_valid(char *path)
{
	if (path == NULL) {
		return (B_FALSE);
	} else if (strlen(path) > PATH_MAX) {
		return (B_FALSE);
	} else if (strlen(path) >= 1) {
		return (B_TRUE);
	} else {
		/* path < 1 */
		return (B_FALSE);
	}
}

/*
 * Name:		web_cleanup
 * Description:	Deletes temp files, closes, frees memory taken
 *		by 'ps' static structure
 *
 * Arguments:	none
 *
 * Returns :	none
 */
void
web_cleanup(void)
{
	PKG_ERR *err;

	if (ps == NULL)
		return;

	err = pkgerr_new();

	if (ps->keystore) {
		(void) close_keystore(err, ps->keystore, NULL);
	}

	ps->keystore = NULL;

	pkgerr_free(err);

	if (ps->uniqfile) {
		(void) remove_dwnld_file(ps->uniqfile);
		free(ps->uniqfile);
		ps->uniqfile = NULL;
	}
	if (ps->link) {
		(void) remove_dwnld_file(ps->link);
		free(ps->link);
		ps->link = NULL;
	}
	if (ps->dwnld_dir) {
	    (void) rmdir(ps->dwnld_dir);
	    ps->dwnld_dir = NULL;
	}
	if (ps->errstr) {
	    free(ps->errstr);
	    ps->errstr = NULL;
	}

	if (ps->content) {
	    free(ps->content);
	    ps->content = NULL;
	}

	if (ps->resp) {
		http_free_respinfo(ps->resp);
		ps->resp = NULL;
	}

	if (ps) {
	    free(ps);
	    ps = NULL;
	}
}

/*
 * Name:		web_session_control
 * Description:	Downloads an arbitrary URL and saves to disk.
 *
 * Arguments:	err - where to record any errors.
 *     		url - URL pointing to content to download - can be
 *			http:// or https://
 *		dwnld_dir - Directory to download into
 *		keystore - keystore to use for accessing trusted
 *			certs when downloading using SSL
 *		proxy - HTTP proxy to use, or NULL for no proxy
 *		proxy_port - HTTP proxy port to use, ignored
 *			if proxy is NULL
 *		passarg - method to retrieve password
 *		retries - # of times to retry download before
 *			giving up
 *		timeout - how long to wait before retrying,
 *			when download is interrupted
 *		nointeract - if non-zero, do not output
 *			download progress to screen
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise
 */
boolean_t
web_session_control(PKG_ERR *err, char *url, char *dwnld_dir,
    keystore_handle_t keystore, char *proxy, ushort_t proxy_port,
    int retries, int timeout, int nointeract, char **fname)
{
	int i;
	boolean_t ret = B_TRUE;
	boolean_t retrieved = B_FALSE;

	if (!init_session()) {
	    ret = B_FALSE;
	    goto cleanup;
	}

	if (!parse_url_proxy(err, url, proxy, proxy_port)) {
		ret = B_FALSE;
		goto cleanup;
	}

	ps->timeout = timeout;

	if (keystore != NULL)
		ps->keystore = keystore;

	if (dwnld_dir != NULL)
		ps->dwnld_dir = xstrdup(dwnld_dir);
	else {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_NO_DWNLD_DIR));
		ret = B_FALSE;
		goto cleanup;
	}

	if (!check_dwnld_dir(err, dwnld_dir)) {
		ret = B_FALSE;
		goto cleanup;
	}

	for (i = 0; i < retries && !retrieved; i++) {
		if (!web_setup(err)) {
			ret = B_FALSE;
			goto cleanup;
		}

		switch (web_connect(err)) {
		    /* time out and wait a little bit for these failures */
		case WEB_OK:
		    /* were able to connect */
			reset_backoff();
			break;
		case WEB_TIMEOUT:
			echo_out(nointeract, gettext(MSG_DWNLD_TIMEOUT));
			(void) web_disconnect();
			backoff();
			continue;

		case WEB_CONNREFUSED:
			echo_out(nointeract, gettext(MSG_DWNLD_CONNREF),
			    ps->url.hport.hostname);
			(void) web_disconnect();
			backoff();
			continue;
		case WEB_HOSTDOWN:
			echo_out(nointeract, gettext(MSG_DWNLD_HOSTDWN),
			    ps->url.hport.hostname);
			(void) web_disconnect();
			backoff();
			continue;

		default:
			/* every other failure is a hard failure, so bail */
			ret = B_FALSE;
			goto cleanup;
		}

		switch (web_send_request(err, HTTP_REQ_TYPE_HEAD,
				ps->data.cur_pos, ps->data.content_length)) {
		case WEB_OK:
		    /* were able to connect */
			reset_backoff();
			break;
		case WEB_TIMEOUT:
			echo_out(nointeract, gettext(MSG_DWNLD_TIMEOUT));
			(void) web_disconnect();
			backoff();
			continue;

		case WEB_CONNREFUSED:
			echo_out(nointeract, gettext(MSG_DWNLD_CONNREF),
			    ps->url.hport.hostname);
			(void) web_disconnect();
			backoff();
			continue;
		case WEB_HOSTDOWN:
			echo_out(nointeract, gettext(MSG_DWNLD_HOSTDWN),
			    ps->url.hport.hostname);
			(void) web_disconnect();
			backoff();
			continue;
		default:
			/* every other case is failure, so bail */
			ret = B_FALSE;
			goto cleanup;
		}

		if (!web_eval_headers(err)) {
			ret = B_FALSE;
			goto cleanup;
		}

		switch (web_get_file(err, dwnld_dir, nointeract, fname)) {
		case WEB_OK:
			/* were able to retrieve file */
			retrieved = B_TRUE;
			reset_backoff();
			break;

		case WEB_TIMEOUT:
			echo_out(nointeract, gettext(MSG_DWNLD_TIMEOUT));
			(void) web_disconnect();
			backoff();
			continue;

		case WEB_CONNREFUSED:
			echo_out(nointeract, gettext(MSG_DWNLD_CONNREF),
			    ps->url.hport.hostname);
			(void) web_disconnect();
			backoff();
			continue;
		case WEB_HOSTDOWN:
			echo_out(nointeract, gettext(MSG_DWNLD_HOSTDWN),
			    ps->url.hport.hostname);
			(void) web_disconnect();
			backoff();
			continue;
		default:
			/* every other failure is a hard failure, so bail */
			ret = B_FALSE;
			goto cleanup;
		}
	}

	if (!retrieved) {
		/* max retries attempted */
		pkgerr_add(err, PKGERR_WEB,
		    gettext(ERR_DWNLD_FAILED), retries);
		ret = B_FALSE;
	}
cleanup:
	(void) web_disconnect();
	if (!ret) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_DWNLD), url);
	}
	return (ret);
}

/*
 * Name:		get_signature
 * Description:	retrieves signature from signed package.
 *
 * Arguments:	err - where to record any errors.
 *		ids_name - name of package stream, for error reporting
 *     		devp - Device on which package resides that we
 *		result - where to store resulting PKCS7 signature
 *
 * Returns :	B_TRUE - package is signed and signature returned OR
 *		package is not signed, in which case result is NULL
 *
 *		B_FALSE - there were problems accessing signature,
 *		and it is unknown whether it is signed or not.  Errors
 *		recorded in 'err'.
 */
boolean_t
get_signature(PKG_ERR *err, char *ids_name, struct pkgdev *devp, PKCS7 **result)
{
	char path[PATH_MAX];
	int len, fd = -1;
	struct stat buf;
	FILE *fp = NULL;
	boolean_t	ret = B_TRUE;
	BIO	*sig_in = NULL;
	PKCS7	*p7 = NULL;

	/*
	 * look for signature.  If one was in the stream,
	 * it is now extracted
	 */
	if (((len = snprintf(path, PATH_MAX, "%s/%s", devp->dirname,
	    SIGNATURE_FILENAME)) >= PATH_MAX) || (len < 0)) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_LEN), ids_name);
		ret = B_FALSE;
		goto cleanup;
	}

	if ((fd = open(path, O_RDONLY|O_NONBLOCK)) == -1) {
		/*
		 * only if the signature is non-existant
		 * do we "pass"
		 */
		if (errno != ENOENT) {
			pkgerr_add(err, PKGERR_WEB, gettext(ERR_OPENSIG),
			    strerror(errno));
			ret = B_FALSE;
			goto cleanup;
		}
	} else {
		/* found sig file.  parse it. */
		if (fstat(fd, &buf) == -1) {
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_OPENSIG), strerror(errno));
			ret = B_FALSE;
			goto cleanup;
		}

		if (!S_ISREG(buf.st_mode)) {
			pkgerr_add(err, PKGERR_WEB, gettext(ERR_OPENSIG),
			    (gettext(ERR_NOT_REG)));
			ret = B_FALSE;
			goto cleanup;
		}

		if ((fp = fdopen(fd, "r")) == NULL) {
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_OPENSIG), strerror(errno));
			ret = B_FALSE;
			goto cleanup;
		}

		/*
		 * read in signature.  If it's invalid, we
		 * punt, unless we're ignoring it
		 */
		if ((sig_in = BIO_new_fp(fp, BIO_NOCLOSE)) == NULL) {
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_OPENSIG), strerror(errno));
			goto cleanup;
		}

		if ((p7 = PEM_read_bio_PKCS7(sig_in,
		    NULL, NULL, NULL)) == NULL) {
			pkgerr_add(err, PKGERR_WEB, gettext(ERR_CORRUPTSIG),
			    ids_name);
			ret = B_FALSE;
			goto cleanup;
		}
		*result = p7;
		p7 = NULL;
	}

cleanup:
	if (sig_in)
		(void) BIO_free(sig_in);
	if (fp)
		(void) fclose(fp);
	if (fd != -1)
		(void) close(fd);
	if (p7)
		(void) PKCS7_free(p7);

	return (ret);
}

/*
 * Name:		echo_out
 * Description:	Conditionally output a message to stdout
 *
 * Arguments:	nointeract - if non-zero, do not output anything
 *		fmt - print format
 *		... - print arguments
 *
 * Returns :	none
 */
void
echo_out(int nointeract, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (nointeract)
		return;

	(void) vfprintf(stdout, fmt, ap);

	va_end(ap);

	(void) putc('\n', stdout);
}

/*
 * Name:		strip_port
 * Description:	Returns "port" portion of a "hostname:port" string
 *
 * Arguments:	proxy - full "hostname:port" string pointer
 *
 * Returns :	the "port" portion of a "hostname:port" string,
 *		converted to a decimal integer, or (int)0
 *		if string contains no :port suffix.
 */
ushort_t
strip_port(char *proxy)
{
	char *tmp_port;

	if ((tmp_port = strpbrk(proxy, ":")) != NULL)
		return (atoi(tmp_port));
	else
		return (0);
}

/*
 * Name:		set_web_install
 * Description:	Sets flag indicating we are doing a web-based install
 *
 * Arguments:	none
 *
 * Returns :	none
 */
void
set_web_install(void)
{
	webpkg_install++;
}

/*
 * Name:		is_web_install
 * Description:	Determines whether we are doing a web-based install
 *
 * Arguments:	none
 *
 * Returns :	non-zero if we are doing a web-based install, 0 otherwise
 */
int
is_web_install(void)
{
	return (webpkg_install);
}

/* ~~~~~~~~~~~~~~ Private Functions ~~~~~~~~~~~~~~~~~~~ */

/*
 * Name:		web_disconnect
 * Description:	Disconnects connection to web server
 *
 * Arguments:	none
 *
 * Returns :	B_TRUE - successful disconnect, B_FALSE otherwise
 *		Temp certificiate files are deleted,
 *		if one was used to initiate the connection
 *		(such as when using SSL)
 */
static boolean_t
web_disconnect(void)
{
	if (ps->certfile) {
		(void) unlink(ps->certfile);
	}
	if (http_srv_disconnect(ps->hps) == 0)
		if (http_srv_close(ps->hps) == 0)
			return (B_TRUE);

	return (B_FALSE);
}

/*
 * Name:		check_dwnld_dir
 * Description:	Creates temp download directory
 *
 * Arguments:	err - where to record any errors.
 *     		dwnld_dir - name of directory to create
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise
 *		on success, directory is created with
 *		safe permissions
 */
static boolean_t
check_dwnld_dir(PKG_ERR *err, char *dwnld_dir)
{
	DIR *dirp;

	/*
	 * Check the directory passed in. If it doesn't exist, create it
	 * with strict permissions
	 */
	if ((dirp = opendir(dwnld_dir)) == NULL) {
		if (mkdir(dwnld_dir, 0744) == -1) {
			pkgerr_add(err, PKGERR_WEB, gettext(MSG_NOTEMP),
			    dwnld_dir);
			return (B_FALSE);
		}
	}
	if (dirp) {
		(void) closedir(dirp);
	}
	return (B_TRUE);
}

/*
 * Name:		ds_validate_signature
 * Description:	Validates signature found in a package datastream
 *
 * Arguments:	err - where to record any errors.
 *		pkgdev - Package context handle of package to verify
 *		pkgs - Null-terminated List of package name to verify
 *		ids_name - Pathname to stream to validate
 *		p7 - PKCS7 signature decoded from stream header
 *		cas - List of trusted CA certificates
 *		proxy - Proxy to use when doing online validation (OCSP)
 *		nointeract - if non-zero, do not output to screen
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise
 *		success means signature was completely validated,
 *		and contents of stream checked against signature.
 */
boolean_t
ds_validate_signature(PKG_ERR *err, struct pkgdev *pkgdev, char **pkgs,
    char *ids_name, PKCS7 *p7, STACK_OF(X509) *cas,
    url_hport_t *proxy, int nointeract)
{
	BIO			 *p7_bio;
	boolean_t		ret = B_TRUE;

	/* make sure it's a Signed PKCS7 message */
	if (!PKCS7_type_is_signed(p7)) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_CORRUPTSIG_TYPE),
		    ids_name);
		ret = B_FALSE;
		goto cleanup;
	}

	/* initialize PKCS7 object to be filled in */
	if (!PKCS7_get_detached(p7)) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_CORRUPTSIG_DT),
		    ids_name);
		ret = B_FALSE;
		goto cleanup;
	}

	/* dump header and packages into BIO to calculate the message digest */
	if ((p7_bio = PKCS7_dataInit(p7, NULL)) == NULL) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_CORRUPTSIG),
		    ids_name);
		ret = B_FALSE;
		goto cleanup;
	}

	if ((BIO_ds_dump_header(err, p7_bio) != 0) ||
	    (BIO_ds_dump(err, ids_name, p7_bio) != 0)) {
		ret = B_FALSE;
		goto cleanup;
	}
	(void) BIO_flush(p7_bio);

	/* validate the stream and its signature */
	if (!validate_signature(err, ids_name, p7_bio, p7, cas,
	    proxy, nointeract)) {
		ret = B_FALSE;
		goto cleanup;
	}

	/* reset device stream (really bad performance for tapes) */
	(void) ds_close(1);
	(void) ds_init(ids_name, pkgs, pkgdev->norewind);

cleanup:
	return (ret);
}


/*
 * Name:		validate_signature
 * Description:	Validates signature of an arbitrary stream of bits
 *
 * Arguments:	err - where to record any errors.
 *		name - Descriptive name of object being validated,
 *			for good error reporting messages
 *		indata - BIO object to read stream bits from
 *		p7 - PKCS7 signature of stream
 *		cas - List of trusted CA certificates
 *		proxy - Proxy to use when doing online validation (OCSP)
 *		nointeract - if non-zero, do not output to screen
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise
 *		success means signature was completely validated,
 *		and contents of stream checked against signature.
 */
boolean_t
validate_signature(PKG_ERR *err, char *name, BIO *indata, PKCS7 *p7,
    STACK_OF(X509) *cas, url_hport_t *proxy, int nointeract)
{
	STACK_OF(PKCS7_SIGNER_INFO) *sec_sinfos = NULL;

	PKCS7_SIGNER_INFO	*signer = NULL;
	X509_STORE		*sec_truststore = NULL;
	X509_STORE_CTX		*ctx = NULL;
	X509			*signer_cert = NULL, *issuer = NULL;
	STACK_OF(X509)		*chaincerts = NULL;
	int			i, k;
	unsigned long		errcode;
	const char		*err_data = NULL;
	const char		*err_reason = NULL;
	char			*err_string;
	int			err_flags;
	verify_cb_data_t	verify_data;
	char			*signer_sname;
	char			*signer_iname;
	PKCS7_ISSUER_AND_SERIAL	*ias;
	boolean_t		ret = B_TRUE;

	/* only support signed PKCS7 signatures */
	if (!PKCS7_type_is_signed(p7)) {
	    PKCS7err(PKCS7_F_PKCS7_DATAVERIFY, PKCS7_R_WRONG_PKCS7_TYPE);
	    ret = B_FALSE;
	    goto cleanup;
	}

	/* initialize temporary internal trust store used for verification */
	sec_truststore = X509_STORE_new();

	for (i = 0; i < sk_X509_num(cas); i++) {
		if (X509_STORE_add_cert(sec_truststore,
		    sk_X509_value(cas, i)) == 0) {
			pkgerr_add(err, PKGERR_VERIFY, gettext(ERR_MEM));
			ret = B_FALSE;
			goto cleanup;
		}
	}

	/* get signers from the signature */
	if ((sec_sinfos = PKCS7_get_signer_info(p7)) == NULL) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_CORRUPTSIG), name);
		ret = B_FALSE;
		goto cleanup;
	}

	/* verify each signer found in the PKCS7 signature */
	for (k = 0; k < sk_PKCS7_SIGNER_INFO_num(sec_sinfos); k++) {
		signer = sk_PKCS7_SIGNER_INFO_value(sec_sinfos, k);
		signer_cert = PKCS7_cert_from_signer_info(p7, signer);
		signer_sname = get_subject_display_name(signer_cert);
		signer_iname = get_issuer_display_name(signer_cert);

		echo_out(nointeract, gettext(MSG_VERIFY), signer_sname);

		/* find the issuer of the current cert */
		chaincerts = p7->d.sign->cert;
		ias = signer->issuer_and_serial;
		issuer = X509_find_by_issuer_and_serial(chaincerts,
		    ias->issuer, ias->serial);

		/* were we not able to find the issuer cert */
		if (issuer == NULL) {
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_VERIFY_ISSUER),
			    signer_iname, signer_sname);
			ret = B_FALSE;
			goto cleanup;
		}

		/* Lets verify */
		if ((ctx = X509_STORE_CTX_new()) == NULL) {
			pkgerr_add(err, PKGERR_VERIFY, gettext(ERR_MEM));
			ret = B_FALSE;
			goto cleanup;
		}
		(void) X509_STORE_CTX_init(ctx, sec_truststore,
		    issuer, chaincerts);
		(void) X509_STORE_CTX_set_purpose(ctx,
		    X509_PURPOSE_ANY);

		/* callback will perform OCSP on certificates with OCSP data */
		X509_STORE_CTX_set_verify_cb(ctx, web_verify);

		/* pass needed data into callback through the app_data handle */
		verify_data.proxy = proxy;
		verify_data.cas = cas;
		verify_data.err = err;
		(void) X509_STORE_CTX_set_app_data(ctx, &verify_data);

		/* first verify the certificate chain */
		i = X509_verify_cert(ctx);
		if (i <= 0 && ctx->error != X509_V_ERR_CERT_HAS_EXPIRED) {
			signer_sname =
			    get_subject_display_name(ctx->current_cert);
			signer_iname =
			    get_issuer_display_name(ctx->current_cert);
			/* if the verify context holds an error, print it */
			if (ctx->error != X509_V_OK) {
				pkgerr_add(err, PKGERR_VERIFY,
				    gettext(ERR_VERIFY_SIG), signer_sname,
				    signer_iname,
			    (char *)X509_verify_cert_error_string(ctx->error));
			} else {
				/* some other error.  print them all. */
				while ((errcode = ERR_get_error_line_data(NULL,
				    NULL, &err_data, &err_flags)) != 0) {
					err_reason =
					    ERR_reason_error_string(errcode);
					if (err_reason == NULL) {
						err_reason =
						    gettext(ERR_SIG_INT);
					}

					if (!(err_flags & ERR_TXT_STRING)) {
						err_data =
						    gettext(ERR_SIG_INT);
					}
					err_string =
					    xmalloc(strlen(err_reason) +
						strlen(err_data) + 3);
					(void) sprintf(err_string, "%s: %s",
					    err_reason, err_data);
					pkgerr_add(err, PKGERR_VERIFY,
					    gettext(ERR_VERIFY_SIG),
					    signer_sname, signer_iname,
					    err_string);
					free(err_string);
				}
			}
			ret = B_FALSE;
			goto cleanup;
		}

		/* now verify the signature */
		i = PKCS7_signatureVerify(indata, p7, signer, issuer);

		if (i <= 0) {
			/* print out any OpenSSL-specific errors */
			signer_sname =
			    get_subject_display_name(ctx->current_cert);
			signer_iname =
			    get_subject_display_name(ctx->current_cert);
			while ((errcode = ERR_get_error_line_data(NULL,
			    NULL, &err_data, &err_flags)) != 0) {
				err_reason =
				    ERR_reason_error_string(errcode);
				if (err_reason == NULL) {
					err_reason =
					    gettext(ERR_SIG_INT);
				}

				if (!(err_flags & ERR_TXT_STRING)) {
					err_data =
					    gettext(ERR_SIG_INT);
				}
				pkgerr_add(err, PKGERR_VERIFY,
				    gettext(ERR_VERIFY_SIG), signer_sname,
				    signer_iname, err_reason);
				pkgerr_add(err, PKGERR_VERIFY,
				    gettext(ERR_VERIFY_SIG), signer_sname,
				    signer_iname, err_data);
			}
			ret = B_FALSE;
			goto cleanup;
		}

		echo_out(nointeract, gettext(MSG_VERIFY_OK), signer_sname);
	}

	/* signature(s) verified successfully */
cleanup:
	if (ctx)
		X509_STORE_CTX_cleanup(ctx);
	return (ret);
}

/*
 * Name:		web_verify
 * Description:	Callback used by PKCS7_dataVerify when
 *		verifying a certificate chain.
 *
 * Arguments:	err - where to record any errors.
 *     		ctx - The context handle of the current verification operation
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise
 *		if it's '0' (not OK) we simply return it, since the
 *		verification operation has already determined that the
 *		cert is invalid.  if 'ok' is non-zero, then we do our
 *		checks, and return 0 or 1 based on if the cert is
 *		invalid or valid.
 */
static int
web_verify(int ok, X509_STORE_CTX *ctx)
{
	X509	*curr_cert;
	X509	*curr_issuer;
	char	*uri;
	url_hport_t	*proxy;
	PKG_ERR	*err = NULL;
	STACK_OF(X509) *cas;
	if (!ok) {
		/* don't override a verify failure */
		return (ok);
	}


	/* get app data supplied through callback context */
	err = ((verify_cb_data_t *)X509_STORE_CTX_get_app_data(ctx))->err;
	proxy = ((verify_cb_data_t *)X509_STORE_CTX_get_app_data(ctx))->proxy;
	cas = ((verify_cb_data_t *)X509_STORE_CTX_get_app_data(ctx))->cas;

	/* Check revocation status */
	curr_cert = X509_STORE_CTX_get_current_cert(ctx);

	/* this shouldn't happen */
	if (curr_cert == NULL) {
		pkgerr_add(err, PKGERR_INTERNAL, gettext(ERR_PKG_INTERNAL),
		    __FILE__, __LINE__);
		return (0);
	}

	/* don't perform OCSP unless cert has required OCSP extensions */
	if (get_ocsp_uri(curr_cert, &uri)) {
		if (get_issuer(&curr_issuer, ctx, curr_cert) <= 0) {
			/* no issuer! */
			pkgerr_add(err, PKGERR_INTERNAL,
			    gettext(ERR_PKG_INTERNAL),
			    __FILE__, __LINE__);
			return (0);
		}

		/*
		 * ok we have the current cert
		 * and its issuer.  Do the OCSP check
		 */

		/*
		 * OCSP extensions are, by, RFC 2459, never critical
		 * extensions, therefore, we only fail if we were able
		 * to explicitly contact an OCSP responder, and that
		 * responder did not indicate the cert was valid.  We
		 * also fail if user-supplied data could not be parsed
		 * or we run out of memory.  We succeeed for "soft"
		 * failures, such as not being able to connect to the
		 * OCSP responder, or trying to use if the OCSP URI
		 * indicates SSL must be used (which we do not
		 * support)
		 */
		switch (ocsp_verify(err, curr_cert, curr_issuer,
		    uri, proxy, cas)) {
		case OCSPMem:		/* Ran out of memory */
		case OCSPInternal:	/* Some internal error */
		case OCSPVerify:	/* OCSP responder indicated fail */
			return (0);
		}
		/* all other cases are success, or soft failures */
		pkgerr_clear(err);
	}

	return (ok);
}

/*
 * Name:		get_time_string
 * Description:	Generates a human-readable string from an ASN1_GENERALIZED_TIME
 *
 * Arguments:	intime - The time to convert
 *
 * Returns :	A pointer to a static string representing the passed-in time.
 */
static char
*get_time_string(ASN1_GENERALIZEDTIME *intime)
{

	static char	time[ATTR_MAX];
	BIO		*mem;
	char	*p;

	if (intime == NULL) {
		return (NULL);
	}
	if ((mem = BIO_new(BIO_s_mem())) == NULL) {
		return (NULL);
	}

	if (ASN1_GENERALIZEDTIME_print(mem, intime) == 0) {
		(void) BIO_free(mem);
		return (NULL);
	}

	if (BIO_gets(mem, time, ATTR_MAX) <= 0) {
		(void) BIO_free(mem);
		return (NULL);
	}

	(void) BIO_free(mem);

	/* trim the end of the string */
	for (p = time + strlen(time) - 1; isspace(*p); p--) {
		*p = '\0';
	}

	return (time);
}

/*
 * Name:		get_ocsp_uri
 * Description:	Examines an X509 certificate and retrieves the embedded
 *		OCSP Responder URI if one exists.
 *
 * Arguments:	cert - The cert to inspect
 *     		uri - pointer where the newly-allocated URI is placed, if found
 *
 * Returns :	Success if the URI was found.  Appropriate status otherwise.
 */
static boolean_t
get_ocsp_uri(X509 *cert, char **uri)
{
	AUTHORITY_INFO_ACCESS		*aia;
	ACCESS_DESCRIPTION		*ad;
	int				i;

	if (getenv("PKGWEB_TEST_OCSP")) {
		*uri = xstrdup(getenv("PKGWEB_TEST_OCSP"));
		return (B_TRUE);
	}

	/* get the X509v3 extension holding the OCSP URI */
	if ((aia = X509_get_ext_d2i(cert, NID_info_access,
	    NULL, NULL)) != NULL) {
		for (i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
			ad = sk_ACCESS_DESCRIPTION_value(aia, i);
			if (OBJ_obj2nid(ad->method) == NID_ad_OCSP) {
				if (ad->location->type == GEN_URI) {
					*uri =
		    xstrdup((char *)ASN1_STRING_data(ad->location->d.ia5));
					return (B_TRUE);
				}
			}
		}
	}

	/* no URI was found */
	return (B_FALSE);
}

/*
 * Name:		ocsp_verify
 * Description:	Attempts to contact an OCSP Responder and ascertain the validity
 *		of an X509 certificate.
 *
 * Arguments:	err - Error object to add error messages to
 *		cert - The cert to validate
 *		issuer - The certificate of the issuer of 'cert'
 *     		uri - The OCSP Responder URI
 *		cas - The trusted CA certificates used to verify the
 *		signed OCSP response
 * Returns :	Success - The OCSP Responder reported a 'good'
 *		status for the cert otherwise, appropriate
 *		error is returned.
 */
static OCSPStatus
ocsp_verify(PKG_ERR *err, X509 *cert, X509 *issuer,
    char *uri, url_hport_t *proxy, STACK_OF(X509) *cas)
{
	OCSP_CERTID		*id;
	OCSP_REQUEST		*req;
	OCSP_RESPONSE		*resp;
	OCSP_BASICRESP		*bs;
	BIO			*cbio, *mem;
	char			ocspbuf[OCSP_BUFSIZ];
	char *host = NULL, *portstr = NULL, *path = "/", *p, *q, *r;
	int		port, status, reason;
	int	len, retval, respcode, use_ssl = 0;
	ASN1_GENERALIZEDTIME	*rev, *thisupd, *nextupd;
	char	*subjname;
	time_t			currtime;
	char			currtimestr[ATTR_MAX];
	unsigned long		errcode;
	const char		*err_reason;

	subjname = get_subject_display_name(cert);

	/* parse the URI into its constituent parts */
	if (OCSP_parse_url(uri, &host, &portstr, &path, &use_ssl) == NULL) {
		pkgerr_add(err, PKGERR_PARSE, gettext(ERR_OCSP_PARSE), uri);
		return (OCSPParse);
	}

	/* we don't currently support SSL-based OCSP Responders */
	if (use_ssl) {
		pkgerr_add(err, PKGERR_PARSE, gettext(ERR_OCSP_UNSUP), uri);
		return (OCSPUnsupported);
	}

	/* default port if none specified */
	if (portstr == NULL) {
		port = (int)URL_DFLT_SRVR_PORT;
	} else {
		port = (int)strtoul(portstr, &r, 10);
		if (*r != '\0') {
			pkgerr_add(err, PKGERR_PARSE,
			    gettext(ERR_OCSP_PARSE), uri);
			return (OCSPParse);
		}
	}

	/* allocate new request structure */
	if ((req = OCSP_REQUEST_new()) == NULL) {
		pkgerr_add(err, PKGERR_PARSE, gettext(ERR_MEM));
		return (OCSPMem);
	}

	/* convert cert and issuer fields into OCSP request data */
	if ((id = OCSP_cert_to_id(NULL, cert, issuer)) == NULL) {
		pkgerr_add(err, PKGERR_PARSE, gettext(ERR_PKG_INTERNAL),
		    __FILE__, __LINE__);
		return (OCSPInternal);
	}

	/* fill out request structure with request data */
	if ((OCSP_request_add0_id(req, id)) == NULL) {
		pkgerr_add(err, PKGERR_PARSE, gettext(ERR_PKG_INTERNAL),
		    __FILE__, __LINE__);
		return (OCSPInternal);
	}

	/* add nonce */
	OCSP_request_add1_nonce(req, NULL, -1);

	/* connect to host, or proxy */
	if (proxy != NULL) {
		if ((cbio = BIO_new_connect(proxy->hostname)) == NULL) {
			pkgerr_add(err, PKGERR_PARSE, gettext(ERR_MEM));
			return (OCSPMem);
		}

		/*
		 * BIO_set_conn_int_port takes an int *, so let's give it one
		 * rather than an ushort_t *
		 */
		port = proxy->port;
		(void) BIO_set_conn_int_port(cbio, &port);
		if (BIO_do_connect(cbio) <= 0) {
			pkgerr_add(err, PKGERR_PARSE,
			    gettext(ERR_OCSP_CONNECT),
			    proxy->hostname, port);
			return (OCSPConnect);
		}
	} else {
		if ((cbio = BIO_new_connect(host)) == NULL) {
			pkgerr_add(err, PKGERR_PARSE, gettext(ERR_MEM));
			return (OCSPMem);
		}

		(void) BIO_set_conn_int_port(cbio, &port);
		if (BIO_do_connect(cbio) <= 0) {
			pkgerr_add(err, PKGERR_PARSE,
			    gettext(ERR_OCSP_CONNECT),
			    host, port);
			return (OCSPConnect);
		}
	}

	/* calculate length of binary request data */
	len = i2d_OCSP_REQUEST(req, NULL);

	/* send the request headers */
	if (proxy != NULL) {
		retval = BIO_printf(cbio, OCSP_REQUEST_FORMAT, uri, len);
	} else {
		retval = BIO_printf(cbio, OCSP_REQUEST_FORMAT, path, len);
	}

	if (retval <= 0) {
		pkgerr_add(err, PKGERR_PARSE, gettext(ERR_OCSP_SEND), host);
		return (OCSPRequest);
	}

	/* send the request binary data */
	if (i2d_OCSP_REQUEST_bio(cbio, req) <= 0) {
		pkgerr_add(err, PKGERR_PARSE, gettext(ERR_OCSP_SEND), host);
		return (OCSPRequest);
	}

	/*
	 * read the response into a memory BIO, so we can 'gets'
	 * (socket bio's don't support BIO_gets)
	 */
	if ((mem = BIO_new(BIO_s_mem())) == NULL) {
		pkgerr_add(err, PKGERR_PARSE, gettext(ERR_MEM));
		return (OCSPMem);
	}

	while ((len = BIO_read(cbio, ocspbuf, OCSP_BUFSIZ))) {
		if (len < 0) {
			pkgerr_add(err, PKGERR_PARSE,
			    gettext(ERR_OCSP_READ), host);
			return (OCSPRequest);
		}
		if (BIO_write(mem, ocspbuf, len) != len) {
			pkgerr_add(err, PKGERR_PARSE, gettext(ERR_MEM));
			return (OCSPMem);
		}
	}

	/* now get the first line of the response */
	if (BIO_gets(mem, ocspbuf, OCSP_BUFSIZ) <= 0) {
		pkgerr_add(err, PKGERR_PARSE, gettext(ERR_OCSP_RESP_PARSE));
		return (OCSPRequest);
	}

	/* parse the header response */
	/* it should look like "HTTP/x.x 200 OK" */

	/* skip past the protocol info */
	for (p = ocspbuf; (*p != '\0') && !isspace(*p); p++)
		continue;

	/* skip past whitespace betwen protocol and start of response code */
	while ((*p != '\0') && isspace(*p)) {
		p++;
	}

	if (*p == '\0') {
		/* premature end */
		pkgerr_add(err, PKGERR_PARSE,
		    gettext(ERR_OCSP_RESP_PARSE), ocspbuf);
		return (OCSPRequest);
	}

	/* find end of response code */
	for (q = p; (*q != NULL) && !isspace(*q); q++)
		continue;

	/* mark end of response code */
	*q++ = '\0';

	/* parse response code */
	respcode = strtoul(p, &r, 10);
	if (*r != '\0') {
		pkgerr_add(err, PKGERR_PARSE,
		    gettext(ERR_OCSP_RESP_PARSE), ocspbuf);
		return (OCSPRequest);
	}

	/* now find beginning of the response string */
	while ((*q != NULL) && isspace(*q)) {
		q++;
	}

	/* trim whitespace from end of message */
	for (r = (q + strlen(q) - 1); isspace(*r); r--) {
		*r = '\0';
	}

	/* response must be OK */
	if (respcode != 200) {
		pkgerr_add(err, PKGERR_PARSE,
		    gettext(ERR_OCSP_RESP_NOTOK), 200,
		    respcode, q);
		return (OCSPRequest);
	}

	/* read headers, looking for content-type or a blank line */
	while (BIO_gets(mem, ocspbuf, OCSP_BUFSIZ) > 0) {

		/* if we get a content type, make sure it's the right type */
		if (ci_strneq(ocspbuf, CONTENT_TYPE_HDR,
		    strlen(CONTENT_TYPE_HDR))) {

			/* look for the delimiting : */
			p = strchr(ocspbuf + strlen(CONTENT_TYPE_HDR), ':');

			if (p == NULL) {
				pkgerr_add(err, PKGERR_PARSE,
				    gettext(ERR_OCSP_RESP_PARSE), ocspbuf);
				return (OCSPResponder);
			}

			/* skip over ':' */
			p++;

			/* find beginning of the content type */
			while ((*p != NULL) && isspace(*p)) {
				p++;
			}

			if (!ci_strneq(p, CONTENT_OCSP_RESP,
			    strlen(CONTENT_OCSP_RESP))) {
				/* response is not right type */
				pkgerr_add(err, PKGERR_PARSE,
				    gettext(ERR_OCSP_RESP_TYPE),
				    p, CONTENT_OCSP_RESP);
				return (OCSPResponder);
			}

			/* continue with next header line */
			continue;
		}

		/* scan looking for a character */
		for (p = ocspbuf; (*p != '\0') && isspace(*p); p++) {
			continue;
		}
		/*
		 * if we got to the end of the line with
		 *  no chars, then this is a blank line
		 */
		if (*p == '\0') {
			break;
		}
	}


	if (*p != '\0') {
		/* last line was not blank */
		pkgerr_add(err, PKGERR_PARSE,
		    gettext(ERR_OCSP_RESP_PARSE), ocspbuf);
		return (OCSPResponder);
	}

	/* now read in the binary response */
	if ((resp = d2i_OCSP_RESPONSE_bio(mem, NULL)) == NULL) {
		pkgerr_add(err, PKGERR_PARSE, gettext(ERR_OCSP_READ), host);
		return (OCSPResponder);
	}

	/* free temp BIOs */
	(void) BIO_free(mem);
	(void) BIO_free_all(cbio);
	cbio = NULL;

	/* make sure request was successful */
	if (OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		pkgerr_add(err, PKGERR_PARSE, gettext(ERR_OCSP_RESP_NOTOK),
		    OCSP_RESPONSE_STATUS_SUCCESSFUL,
		    OCSP_response_status(resp),
		    OCSP_response_status_str(OCSP_response_status(resp)));
		return (OCSPResponder);
	}

	/* parse binary response into internal structure */
	if ((bs = OCSP_response_get1_basic(resp)) == NULL) {
		pkgerr_add(err, PKGERR_PARSE, gettext(ERR_OCSP_READ), host);
		return (OCSPParse);
	}

	/*
	 * From here to the end of the code, the return values
	 * should be hard failures
	 */

	/* verify the response, warn if no nonce */
	if (OCSP_check_nonce(req, bs) <= 0) {
		logerr(pkg_gt(WRN_OCSP_RESP_NONCE));
	}

	if (OCSP_basic_verify(bs, cas, NULL, OCSP_TRUSTOTHER) <= 0) {
		while ((errcode = ERR_get_error()) != NULL) {
			err_reason = ERR_reason_error_string(errcode);
			if (err_reason == NULL) {
				err_reason =
				    gettext(ERR_SIG_INT);
			}
			pkgerr_add(err, PKGERR_PARSE, (char *)err_reason);
		}
		pkgerr_add(err, PKGERR_PARSE, gettext(ERR_OCSP_VERIFY_FAIL),
		    uri);
		return (OCSPVerify);
	}

	/* check the validity of our certificate */
	if (OCSP_resp_find_status(bs, id, &status, &reason,
	    &rev, &thisupd, &nextupd) == NULL) {
		pkgerr_add(err, PKGERR_PARSE,
		    gettext(ERR_OCSP_VERIFY_NO_STATUS), subjname);
		return (OCSPVerify);
	}

	if ((currtime = time(NULL)) == (time_t)-1) {
		pkgerr_add(err, PKGERR_PARSE,
		    gettext(ERR_OCSP_VERIFY_NOTIME));
		return (OCSPVerify);
	}

	(void) strlcpy(currtimestr, ctime(&currtime), ATTR_MAX);

	/* trim end */
	for (r = currtimestr + strlen(currtimestr) - 1;
		isspace(*r); r--) {
		*r = '\0';
	}

	if (!OCSP_check_validity(thisupd, nextupd,
	    OCSP_VALIDITY_PERIOD, -1)) {
		if (nextupd != NULL) {
			pkgerr_add(err, PKGERR_PARSE,
			    gettext(ERR_OCSP_VERIFY_VALIDITY),
			    get_time_string(thisupd), get_time_string(nextupd),
			    currtimestr);
		} else {
			pkgerr_add(err, PKGERR_PARSE,
			    gettext(ERR_OCSP_VERIFY_VALIDITY),
			    get_time_string(thisupd),
			    currtimestr);
		}
		return (OCSPVerify);
	}

	if (status != V_OCSP_CERTSTATUS_GOOD) {
		pkgerr_add(err, PKGERR_PARSE,
		    gettext(ERR_OCSP_VERIFY_STATUS), subjname,
		    OCSP_cert_status_str(status));
		return (OCSPVerify);
	}

	/* everythign checks out */
	return (OCSPSuccess);
}

/*
 * Name:		get_issuer
 * Description:	Attempts to find the issuing certificate for a given certificate
 *		This will look in both the list of trusted certificates found in
 *		the X509_STORE_CTX structure, as well as the list of untrusted
 *		chain certificates found in the X509_STORE_CTX structure.
 * Arguments:
 *		issuer - The resulting issuer cert is placed here, if found
 *		ctx - The current verification context
 *		x - The certificate whose issuer we are looking for
 * Returns :	Success - The issuer cert was found and placed in *issuer.
 *		otherwise, appropriate error is returned.
 */
static int
get_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x)
{
	int		i, ok;

	/*
	 * first look in the list of trusted
	 * certs, using the context's method to do so
	 */
	if ((ok = ctx->get_issuer(issuer, ctx, x)) > 0) {
		return (ok);
	}

	if (ctx->untrusted != NULL) {
		/* didn't find it in trusted certs, look through untrusted */
		for (i = 0; i < sk_X509_num(ctx->untrusted); i++) {
			if (X509_check_issued(sk_X509_value(ctx->untrusted, i),
			    x) == X509_V_OK) {
				*issuer = sk_X509_value(ctx->untrusted, i);
				return (1);
			}
		}
	}
	*issuer = NULL;
	return (0);
}

/*
 * Name:		parse_url_proxy
 * Description:	Parses URL and optional proxy specification, populates static
 *		'ps' structure
 *
 * Arguments:	err - where to record any errors.
 *		url - URL to parse
 *		proxy - proxy to parse, or NULL for no proxy
 *		proxy_port - Default proxy port to use if no proxy
 *		port specified in 'proxy'
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise
 *		on success, 'ps->url' and 'ps->proxy' are populated
 *		with parsed data.
 */
static boolean_t
parse_url_proxy(PKG_ERR *err, char *url, char *proxy, ushort_t proxy_port)
{
	boolean_t ret = B_TRUE;
	if (!path_valid(url)) {
		ret = B_FALSE;
		goto cleanup;
	}

	if (url_parse(url, &ps->url) != URL_PARSE_SUCCESS) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_PARSE_URL), url);
		ret = B_FALSE;
		goto cleanup;
	}

	if (proxy != NULL) {
		if (url_parse_hostport(proxy, &ps->proxy, proxy_port)
				!= URL_PARSE_SUCCESS) {
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_BAD_PROXY), proxy);
			ret = B_FALSE;
			goto cleanup;
		}
	}

cleanup:
	return (ret);
}

/*
 * Name:		web_setup
 * Description:	Initializes http library settings
 *
 * Arguments:	err - where to record any errors.
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise
 */
static boolean_t
web_setup(PKG_ERR *err)
{
	boolean_t ret = B_TRUE;
	static boolean_t keepalive = B_TRUE;

	if ((ps->hps = http_srv_init(&ps->url)) == NULL) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_INIT_SESS), ps->url);
		ret = B_FALSE;
		goto cleanup;
	}

	if (getenv("WEBPKG_DEBUG") != NULL) {
		http_set_verbose(B_TRUE);
	}

	if (ps->proxy.hostname[0] != '\0' &&
			http_set_proxy(ps->hps, &ps->proxy) != 0) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_INIT_SESS), ps->url);
		ret = B_FALSE;
		goto cleanup;
	}
	if (http_set_keepalive(ps->hps, keepalive) != 0) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_INIT_SESS), ps->url);
		ret = B_FALSE;
		goto cleanup;
	}
	if (http_set_socket_read_timeout(ps->hps, ps->timeout) != 0) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_INIT_SESS), ps->url);
		ret = B_FALSE;
		goto cleanup;
	}
	if (http_set_random_file(ps->hps, RANDOM) != 0) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_INIT_SESS), ps->url);
		ret = B_FALSE;
		goto cleanup;
	}

	(void) http_set_p12_format(B_TRUE);

cleanup:
	return (ret);
}

/*
 * Name:		web_connect
 * Description:	Makes connection with URL stored in static 'ps' structure.
 *
 * Arguments:	err - where to record any errors.
 *
 * Returns :   	WEB_OK - connection successful
 *		WEB_VERIFY_SETUP - Unable to complete necessary
 *			SSL setup
 *		WEB_CONNREFUSED - Connection was refused to web site
 *		WEB_HOSTDOWN - Host was not responding to request
 *		WEB_NOCONNECT - Some other connection failure
 */
static WebStatus
web_connect(PKG_ERR *err)
{
	STACK_OF(X509)  *sec_cas = NULL;
	char *path;
	WebStatus ret = WEB_OK;
	ulong_t		errcode;
	uint_t		errsrc;
	int		my_errno = 0;
	const char		*libhttperr = NULL;

	if (ps->url.https == B_TRUE) {
		/* get CA certificates */
		if (find_ca_certs(err, ps->keystore, &sec_cas) != 0) {
			ret = WEB_VERIFY_SETUP;
			goto cleanup;
		}

		if (sk_X509_num(sec_cas) < 1) {
			/* no trusted websites */
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_KEYSTORE_NOTRUST));
			ret = WEB_VERIFY_SETUP;
			goto cleanup;
		}

		/*
		 * write out all CA certs to temp file.  libwanboot should
		 * have an interface for giving it a list of trusted certs
		 * through an in-memory structure, but currently that does
		 * not exist
		 */
		if ((path = write_ca_file(err, ps->dwnld_dir, sec_cas,
		    WEB_CA_PHRASE)) == NULL) {
			ret = WEB_VERIFY_SETUP;
			goto cleanup;
		}

		ps->certfile = path;
		if (http_set_password(ps->hps, WEB_CA_PHRASE) != 0) {
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_HTTPS_PASSWD));
			ret = WEB_VERIFY_SETUP;
			goto cleanup;
		}

		if (http_set_certificate_authority_file(path) != 0) {
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_HTTPS_CA));
			ret = WEB_VERIFY_SETUP;
			goto cleanup;
		}
	}

	if (http_srv_connect(ps->hps) != 0) {
		while ((errcode = http_get_lasterr(ps->hps, &errsrc)) != 0) {
			/* Have an error - is it EINTR? */
			if (errsrc == ERRSRC_SYSTEM) {
				my_errno = errcode;
				break;
			} else if (libhttperr == NULL) {
				/* save the first non-system error message */
				libhttperr = http_errorstr(errsrc, errcode);
			}
		}
		switch (my_errno) {
		case EINTR:
		case ETIMEDOUT:
				/* Timed out.  Try, try again */
			ret = WEB_TIMEOUT;
			break;
		case ECONNREFUSED:
			ret = WEB_CONNREFUSED;
			break;
		case EHOSTDOWN:
			ret = WEB_HOSTDOWN;
			break;
		default:
				/* some other fatal error */
			ret = WEB_NOCONNECT;
			if (libhttperr == NULL) {
				pkgerr_add(err, PKGERR_WEB,
				    gettext(ERR_INIT_CONN),
				    ps->url.hport.hostname);
			} else {
				pkgerr_add(err, PKGERR_WEB,
				    gettext(ERR_HTTP), libhttperr);
			}
			break;
		}
	}
cleanup:
	return (ret);
}

/*
 * Name:		write_ca_file
 * Description:	Writes out a PKCS12 file containing all trusted certs
 *		found in keystore recorded in static 'ps' structure
 *
 *		This routine is used because the libwanboot library's
 *		HTTPS routines cannot accept trusted certificates
 *		through an in-memory structure, when initiating an
 *		SSL connection.  They must be in a PKCS12, which is
 *		admittedly a poor interface.
 *
 * Arguments:	err - where to record any errors.
 *     		tmpdir - Directory to write certificate file in
 *		cacerts - Certs to write out
 *		passwd - password used to encrypt certs
 *
 * Returns :	path to resulting file, if successfullly written,
 *		otherwise NULL.
 */
static char
*write_ca_file(PKG_ERR *err, char *tmpdir, STACK_OF(X509) *cacerts,
    char *passwd)
{
	int fd, len;
	FILE *fp;
	PKCS12	*p12 = NULL;
	char *ret = NULL;
	static char tmp_file[PATH_MAX] = "";
	struct stat buf;

	if (!path_valid(tmpdir)) {
		pkgerr_add(err, PKGERR_WEB, gettext(MSG_NOTEMP), tmpdir);
		goto cleanup;
	}

	/* mkstemp replaces XXXXXX with a unique string */
	if (((len = snprintf(tmp_file, PATH_MAX, "%s/%sXXXXXX", tmpdir,
	    "cert")) < 0) ||
	    (len >= PATH_MAX)) {
		pkgerr_add(err, PKGERR_WEB, gettext(MSG_NOTEMP), tmpdir);
		goto cleanup;
	}

	if ((fd = mkstemp(tmp_file)) == -1) {
		pkgerr_add(err, PKGERR_WEB, gettext(MSG_NOTMPFIL), tmp_file);
		goto cleanup;
	}

	if (fstat(fd, &buf) == -1) {
		pkgerr_add(err, PKGERR_WEB, gettext(MSG_NOTMPFIL), tmp_file);
		goto cleanup;
	}

	if (!S_ISREG(buf.st_mode)) {
		pkgerr_add(err, PKGERR_WEB, gettext(MSG_NOTMPFIL), tmp_file);
		goto cleanup;
	}

	if ((fp = fdopen(fd, "w")) == NULL) {
		pkgerr_add(err, PKGERR_WEB, gettext(MSG_NOTMPFIL), tmp_file);
		goto cleanup;
	}

	if ((p12 = sunw_PKCS12_create(passwd, NULL, NULL, cacerts)) == NULL) {
		pkgerr_add(err, PKGERR_WEB,
		    gettext(ERR_KEYSTORE_FORM), tmp_file);
		goto cleanup;
	}

	if (i2d_PKCS12_fp(fp, p12) == 0) {
		pkgerr_add(err, PKGERR_WEB,
		    gettext(ERR_KEYSTORE_FORM), tmp_file);
		goto cleanup;
	}

	(void) fflush(fp);
	(void) fclose(fp);
	(void) close(fd);
	fp = NULL;
	fd = -1;
	ret = tmp_file;

cleanup:
	if (p12 != NULL)
		PKCS12_free(p12);
	if (fp != NULL)
		(void) fclose(fp);
	if (fd != -1) {
		(void) close(fd);
		(void) unlink(tmp_file);
	}

	return (ret);
}

/*
 * Name:		web_send_request
 * Description:	Sends an HTTP request for a file to the
 *		web server being communicated with in the static
 *		'ps' structure
 *
 * Arguments:	err - where to record any errors.
 *		request_type - HTTP_REQ_TYPE_HEAD to send an HTTP HEAD request,
 *		or HTTP_REQ_TYPE_GET to send an HTTP GET request
 *		cp -
 * Returns :   	WEB_OK - request sent successfully
 *		WEB_CONNREFUSED - Connection was refused to web site
 *		WEB_HOSTDOWN - Host was not responding to request
 *		WEB_NOCONNECT - Some other connection failure
 */
static WebStatus
web_send_request(PKG_ERR *err, int request_type, int cp, int ep)
{
	WebStatus ret = WEB_OK;
	ulong_t		errcode;
	uint_t		errsrc;
	int		my_errno = 0;
	const char		*libhttperr = NULL;
	switch (request_type) {
	case HTTP_REQ_TYPE_HEAD:
		if ((http_head_request(ps->hps, ps->url.abspath)) != 0) {
			while ((errcode = http_get_lasterr(ps->hps,
			    &errsrc)) != 0) {
				/* Have an error - is it EINTR? */
			    if (errsrc == ERRSRC_SYSTEM) {
				    my_errno = errcode;
				    break;
			    } else if (libhttperr == NULL) {
				    /* save first non-system error message */
				    libhttperr =
					http_errorstr(errsrc, errcode);
			    }
			}
			switch (my_errno) {
			    case EINTR:
			case ETIMEDOUT:
				/* Timed out.  Try, try again */
				ret = WEB_TIMEOUT;
				break;
			case ECONNREFUSED:
				ret = WEB_CONNREFUSED;
				break;
			case EHOSTDOWN:
				ret = WEB_HOSTDOWN;
				break;
			default:
				/* some other fatal error */
				ret = WEB_NOCONNECT;
				if (libhttperr == NULL) {
					pkgerr_add(err, PKGERR_WEB,
					    gettext(ERR_INIT_CONN),
					    ps->url.hport.hostname);
				} else {
					pkgerr_add(err, PKGERR_WEB,
					    gettext(ERR_HTTP), libhttperr);
				}
				break;
			}
			goto cleanup;
			}
		break;

	case HTTP_REQ_TYPE_GET:
		if (cp && ep) {
			if (http_get_range_request(ps->hps, ps->url.abspath,
			    cp, ep - cp) != 0) {
				while ((errcode = http_get_lasterr(ps->hps,
				    &errsrc)) != 0) {
					/* Have an error - is it EINTR? */
					if (errsrc == ERRSRC_SYSTEM) {
						my_errno = errcode;
						break;
					} else {
						/*
						 * save first non-system
						 * error message
						 */
						libhttperr =
						    http_errorstr(errsrc,
							errcode);
					}
				}
				switch (my_errno) {
				case EINTR:
				case ETIMEDOUT:
					/* Timed out.  Try, try again */
					ret = WEB_TIMEOUT;
					break;
				case ECONNREFUSED:
					ret = WEB_CONNREFUSED;
					break;
				case EHOSTDOWN:
					ret = WEB_HOSTDOWN;
					break;
				default:
					/* some other fatal error */
					ret = WEB_NOCONNECT;
					if (libhttperr == NULL) {
						pkgerr_add(err, PKGERR_WEB,
						    gettext(ERR_INIT_CONN),
						    ps->url.hport.hostname);
					} else {
						pkgerr_add(err, PKGERR_WEB,
						    gettext(ERR_HTTP),
						    libhttperr);
					}
					break;
				}
				goto cleanup;
			}

			if (!web_eval_headers(err)) {
				ret = WEB_NOCONNECT;
				goto cleanup;
			}
		} else {
			if ((http_get_request(ps->hps, ps->url.abspath))
					!= 0) {
				while ((errcode = http_get_lasterr(ps->hps,
				    &errsrc)) != 0) {
					/* Have an error - is it EINTR? */
					if (errsrc == ERRSRC_SYSTEM) {
						my_errno = errcode;
						break;
					} else {
						/*
						 * save the first non-system
						 * error message
						 */
						libhttperr =
						    http_errorstr(errsrc,
							errcode);
					}
				}
				switch (my_errno) {
				case EINTR:
				case ETIMEDOUT:
					/* Timed out.  Try, try again */
					ret = WEB_TIMEOUT;
					break;
				case ECONNREFUSED:
					ret = WEB_CONNREFUSED;
					break;
				case EHOSTDOWN:
					ret = WEB_HOSTDOWN;
					break;
				default:
					/* some other fatal error */
					ret = WEB_NOCONNECT;
					if (libhttperr == NULL) {
						pkgerr_add(err, PKGERR_WEB,
						    gettext(ERR_INIT_CONN),
						    ps->url.hport.hostname);
					} else {
						pkgerr_add(err, PKGERR_WEB,
						    gettext(ERR_HTTP),
						    libhttperr);
					}
					break;
				}
				goto cleanup;
			}

			if (!web_eval_headers(err)) {
				ret = WEB_NOCONNECT;
				goto cleanup;
			}
		}
		break;
	default:
		pkgerr_add(err, PKGERR_INTERNAL, gettext(ERR_PKG_INTERNAL),
		    __FILE__, __LINE__);
	}

cleanup:
	return (ret);
}

/*
 * Name:		web_eval_headers
 * Description:	Evaluates HTTP headers returned during an HTTP request.
 *		This must be called before calling
 *		http_get_header_value().
 *
 * Arguments:	err - where to record any errors.
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise
 */
static boolean_t
web_eval_headers(PKG_ERR *err)
{
	const char *http_err;
	ulong_t herr;
	uint_t errsrc;

	if (http_process_headers(ps->hps, &ps->resp) != 0) {
		if ((ps->resp != NULL) && (ps->resp->statusmsg != NULL)) {
			pkgerr_add(err, PKGERR_WEB, gettext(ERR_HTTP),
			    ps->resp->statusmsg);
		}

		herr = http_get_lasterr(ps->hps, &errsrc);
		http_err = http_errorstr(errsrc, herr);
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_HTTP),
		    http_err);
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Name:		web_get_file
 * Description:	Downloads the file URL from the website, all of
 *		which are recorded in the static 'ps' struct
 *
 * Arguments:	err - where to record any errors.
 *		dwnld_dir - Directory to download file into
 *		device - Where to store path to resulting
 *			file
 *		nointeract - if non-zero, do not output
 *		progress
 *		fname - name of downloaded file link in the dwnld_dir
 *
 * Returns :   	WEB_OK - download successful
 *		WEB_CONNREFUSED - Connection was refused to web site
 *		WEB_HOSTDOWN - Host was not responding to request
 *		WEB_GET_FAIL - Unable to initialize download
 *		state (temp file creation, header parsing, etc)
 *		WEB_NOCONNECT - Some other connection failure
 */
static WebStatus
web_get_file(PKG_ERR *err, char *dwnld_dir, int nointeract, char **fname)
{
	int		i, fd;
	int		n = 0;
	ulong_t		abs_pos = 0;
	char		*head_val = NULL;
	char		*lastmod_val = NULL;
	char		*bname = NULL;
	struct stat	status;
	WebStatus	ret = WEB_OK;
	WebStatus	req_ret;
	ulong_t		errcode;
	uint_t		errsrc;
	int		my_errno = 0;
	const char	*libhttperr = NULL;
	char		*disp;
	char		tmp_file[PATH_MAX];
	int		len;

	ps->data.prev_cont_length =
	ps->data.content_length =
	ps->data.cur_pos = 0;

	if ((head_val = http_get_header_value(ps->hps,
	    CONTENT_LENGTH_HDR)) != NULL) {
		ps->data.content_length = atol(head_val);
	} else {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_NO_HEAD_VAL),
		    CONTENT_LENGTH_HDR);
		ret = WEB_GET_FAIL;
		goto cleanup;
	}

	free(head_val);
	head_val = NULL;

	if ((head_val = http_get_header_value(ps->hps,
	    CONTENT_DISPOSITION_HDR)) != NULL) {
		/* "inline; parm=val; parm=val */
		if ((disp = strtok(head_val, "; \t\n\f\r")) != NULL) {
			/* disp = "inline" */
			while ((disp = strtok(NULL, "; \t\n\f\r")) != NULL) {
				/* disp = "parm=val" */
				if (ci_strneq(disp, "filename=", 9)) {
					bname = xstrdup(basename(disp + 9));
					trim(bname);
					dequote(bname);
				}
			}
		}
		free(head_val);
		head_val = NULL;
	}

	if (bname == NULL) {
		/*
		 * couldn't determine filename from header value,
		 * so take basename of URL
		 */
		if ((bname = get_endof_string(ps->url.abspath, '/')) == NULL) {
			/* URL is bad */
			pkgerr_add(err, PKGERR_PARSE,
			    gettext(ERR_PARSE_URL), ps->url.abspath);
			ret = WEB_GET_FAIL;
			goto cleanup;
		}
	}

	*fname = bname;

	if ((head_val = http_get_header_value(ps->hps, LAST_MODIFIED_HDR))
			!= NULL) {

		if ((lastmod_val = condense_lastmodified(head_val)) == NULL) {
			pkgerr_add(err, PKGERR_WEB, gettext(ERR_BAD_HEAD_VAL),
			    LAST_MODIFIED_HDR, head_val);
			ret = WEB_GET_FAIL;
			goto cleanup;
		}
		free(head_val);
		head_val = NULL;

		if ((ps->uniqfile = get_unique_filename(dwnld_dir,
		    lastmod_val)) == NULL) {
			pkgerr_add(err, PKGERR_WEB, gettext(ERR_OPEN_TMP));
			ret = WEB_GET_FAIL;
			goto cleanup;
		}

		free(lastmod_val);
		lastmod_val = NULL;

		if ((fd = open(ps->uniqfile,
		    O_NONBLOCK|O_RDWR|O_APPEND|O_CREAT|O_EXCL,
		    640)) == -1) {

			/*
			 * A partial downloaded file
			 * already exists, so open it.
			 */
			if ((fd = open(ps->uniqfile,
			    O_NONBLOCK|O_RDWR|O_APPEND)) != -1) {
				if (fstat(fd, &status) == -1 ||
				    !S_ISREG(status.st_mode)) {
					pkgerr_add(err, PKGERR_WEB,
					    gettext(ERR_DWNLD_NO_CONT),
					    ps->uniqfile);
					ret = WEB_GET_FAIL;
					goto cleanup;
				} else {
					echo_out(nointeract,
					    gettext(MSG_DWNLD_PART),
					    ps->uniqfile,
					    status.st_size);
					ps->data.prev_cont_length =
					    status.st_size;
				}
			} else {
				/* unable to open partial file */
				pkgerr_add(err, PKGERR_WEB,
				    gettext(ERR_DWNLD_NO_CONT),
				    ps->uniqfile);
				ret = WEB_GET_FAIL;
				goto cleanup;
			}
		}
	} else {
		/*
		 * no "Last-Modified" header, so this file is not eligible for
		 * spooling and "resuming last download" operations
		 */
		ps->spool = B_FALSE;

		/* mkstemp replaces XXXXXX with a unique string */
		if (((len = snprintf(tmp_file, PATH_MAX,
		    "%s/%sXXXXXX", dwnld_dir, "stream")) < 0) ||
		    (len >= PATH_MAX)) {
			pkgerr_add(err, PKGERR_WEB,
			    gettext(MSG_NOTEMP), dwnld_dir);
			ret = WEB_GET_FAIL;
			goto cleanup;
		}

		if ((fd = mkstemp(tmp_file)) == -1) {
			pkgerr_add(err, PKGERR_WEB,
			    gettext(MSG_NOTMPFIL), tmp_file);
			ret = WEB_GET_FAIL;
			goto cleanup;
		}

		if (fstat(fd, &status) == -1 ||
		    !S_ISREG(status.st_mode)) {
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_DWNLD_NO_CONT),
			    ps->uniqfile);
			ret = WEB_GET_FAIL;
			goto cleanup;
		}

		ps->data.prev_cont_length = 0;
		ps->uniqfile = xstrdup(tmp_file);
	}

	/* File has already been completely downloaded */
	if (ps->data.prev_cont_length == ps->data.content_length) {
		echo_out(nointeract, gettext(MSG_DWNLD_PREV), ps->uniqfile);
		ps->data.cur_pos = ps->data.prev_cont_length;
		if (!make_link(dwnld_dir, bname)) {
			pkgerr_add(err, PKGERR_WEB, gettext(MSG_NOTEMP),
			    dwnld_dir);
			ret = WEB_GET_FAIL;
			goto cleanup;
		}
		/* we're done, so cleanup and return success */
		goto cleanup;
	} else if (ps->data.prev_cont_length != 0) {
		ps->data.cur_pos = ps->data.prev_cont_length;
	}

	if (!ck_dwnld_dir_space(err, dwnld_dir,
	    (ps->data.prev_cont_length != 0) ?
	    (ps->data.content_length - ps->data.cur_pos) :
	    ps->data.content_length)) {
		ret = WEB_GET_FAIL;
		goto cleanup;
	}

	if ((req_ret = web_send_request(err, HTTP_REQ_TYPE_GET,
	    ps->data.cur_pos, ps->data.content_length)) != WEB_OK) {
		ret = req_ret;
		goto cleanup;
	}

	if (ps->data.prev_cont_length != 0)
		echo_out(nointeract, gettext(MSG_DWNLD_CONT));
	else
		echo_out(nointeract, gettext(MSG_DWNLD));

	progress_setup(nointeract, ps->data.content_length);

	/* Download the file a BLOCK at a time */
	while (ps->data.cur_pos < ps->data.content_length) {
		progress_report(nointeract, abs_pos);
		i = ((ps->data.content_length - ps->data.cur_pos) < BLOCK) ?
		    (ps->data.content_length - ps->data.cur_pos)
				: BLOCK;
		if ((n = http_read_body(ps->hps, ps->content, i)) <= 0) {
			while ((errcode = http_get_lasterr(ps->hps,
			    &errsrc)) != 0) {
				/* Have an error - is it EINTR? */
				if (errsrc == ERRSRC_SYSTEM) {
					my_errno = errcode;
					break;
				} else {
					/*
					 * save first non-system
					 * error message
					 */
					libhttperr =
					    http_errorstr(errsrc, errcode);
				}
			}
			switch (my_errno) {
			case EINTR:
			case ETIMEDOUT:
				/* Timed out.  Try, try again */
				ret = WEB_TIMEOUT;
				break;
			case ECONNREFUSED:
				ret = WEB_CONNREFUSED;
				break;
			case EHOSTDOWN:
				ret = WEB_HOSTDOWN;
				break;
			default:
				/* some other fatal error */
				ret = WEB_NOCONNECT;
				if (libhttperr == NULL) {
					pkgerr_add(err, PKGERR_WEB,
					    gettext(ERR_INIT_CONN),
					    ps->url.hport.hostname);
				} else {
					pkgerr_add(err, PKGERR_WEB,
					    gettext(ERR_HTTP), libhttperr);
				}
				break;
			}
			goto cleanup;
		}
		if ((n = write(fd, ps->content, n)) == 0) {
			pkgerr_add(err, PKGERR_WEB, gettext(ERR_WRITE),
			    ps->uniqfile, strerror(errno));
			ret = WEB_GET_FAIL;
			goto cleanup;
		}
		ps->data.cur_pos += n;
		abs_pos += n;
	}

	progress_finish(nointeract);
	echo_out(nointeract, gettext(MSG_DWNLD_COMPLETE));

	if (!make_link(dwnld_dir, bname)) {
		pkgerr_add(err, PKGERR_WEB, gettext(MSG_NOTEMP),
		    dwnld_dir);
		ret = WEB_GET_FAIL;
		goto cleanup;
	}

cleanup:
	sync();
	if (fd != -1) {
		(void) close(fd);
	}

	if (head_val != NULL)
		free(head_val);

	if (lastmod_val != NULL)
		free(lastmod_val);

	return (ret);
}

/*
 * Name:		make_link
 * Description:	Create new link to file being downloaded
 *
 * Arguments:	dwnld_dir - directory in which downloaded file exists
 *		bname - name of link
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise
 */
static boolean_t
make_link(char *dwnld_dir, char *bname)
{
	int len;

	if ((ps->link = (char *)xmalloc(PATH_MAX)) == NULL)
		return (B_FALSE);
	if (((len = snprintf(ps->link, PATH_MAX, "%s/%s",
	    dwnld_dir, bname)) < 0) ||
	    len >= PATH_MAX)
		return (B_FALSE);

	(void) link(ps->uniqfile, ps->link);

	return (B_TRUE);
}

/*
 * Name:		get_startof_string
 * Description:	searches string for token, returns a newly-allocated
 *		substring of the given string up to, but not
 *		including, token.  for example
 *		get_startof_string("abcd", 'c') will return "ab"
 *
 * Arguments:	path - path to split
 *     		token - character to split on
 *
 * Returns :	substring of 'path', up to, but not including,
 *		token, if token appears in path.  Otherwise,
 *		returns NULL.
 */
char *
get_startof_string(char *path, char token)
{
	char *p, *p2;

	if (path == NULL)
		return (NULL);

	p = xstrdup(path);

	p2 = strchr(p, token);
	if (p2 == NULL) {
		free(p);
		return (NULL);
	} else {
		*p2 = '\0';
		return (p);
	}
}

/*
 * Name:		get_endof_string
 * Description:	searches string for token, returns a
 *		newly-allocated substring of the given string,
 *		starting at character following token, to end of
 *		string.
 *
 *		for example get_end_string("abcd", 'c')
 *		will return "d"
 *
 * Arguments:	path - path to split
 *     		token - character to split on
 *
 * Returns :	substring of 'path', beginning at character
 *		following token, to end of string, if
 *		token appears in path.  Otherwise,
 * returns NULL.
 */
char *
get_endof_string(char *path, char token)
{
	char *p, *p2;

	if (path == NULL)
		return (NULL);

	p = xstrdup(path);

	if ((p2 = strrchr(p, token)) == NULL) {
		return (NULL);
	}

	return (p2 + 1);
}

/*
 * Name:		progress_setup
 * Description:	Initialize session for reporting progress
 *
 * Arguments:	nointeract - if non-zero, do not do anything
 *		ulong_t - size of job to report progress for
 *
 * Returns :	none
 */
static void
progress_setup(int nointeract, ulong_t size_of_load)
{
	ulong_t divisor;
	ulong_t term_width = TERM_WIDTH;

	if (nointeract)
		return;

	if (size_of_load > MED_DWNLD && size_of_load < LARGE_DWNLD)
		divisor = MED_DIVISOR;
	else if (size_of_load > LARGE_DWNLD) {
		term_width = TERM_WIDTH - 8;
		divisor = LARGE_DIVISOR;
	} else
		divisor = SMALL_DIVISOR;

	const_increment = size_of_load / term_width;
	const_divider = size_of_load / divisor;
	const_completed = 100 / divisor;
}

/*
 * Name:		progress_report
 * Description:	Report progress for current progress context,
 *		to stderr
 *
 * Arguments:	nointeract - if non-zero, do not do anything
 *		position - how far along in the job to report.
 *		This should be <= size used during progress_setup
 *
 * Returns :	none
 */
static void
progress_report(int nointeract, ulong_t position)
{
	static ulong_t increment;
	static ulong_t divider;

	if (nointeract)
		return;

	if (position == 0) {
		increment = const_increment;
		divider = const_divider;
	}
	if (position > increment && position < divider) {
		(void) putc('.', stderr);
		increment += const_increment;
	} else if (position > divider) {
		completed += const_completed;
		(void) fprintf(stderr, "%ld%c", completed, '%');
		increment += const_increment;
		divider += const_divider;
	}
}

/*
 * Name:		progress_finish
 * Description:	Finalize session for reporting progress.
 *		"100%" is reported to screen
 *
 * Arguments:	nointeract - if non-zero, do not do anything
 *
 * Returns :	none
 */
static void
progress_finish(int nointeract)
{
	if (nointeract)
		return;

	(void) fprintf(stderr, "%d%c\n", 100, '%');
}

/*
 * Name:		init_session
 * Description:	Initializes static 'ps' structure with default
 *		values
 *
 * Arguments:	none
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise
 */
static boolean_t
init_session(void)
{
	if ((ps = (WEB_SESSION *)
		xmalloc(sizeof (WEB_SESSION))) == NULL) {
		return (B_FALSE);
	}
	(void) memset(ps, 0, sizeof (*ps));

	if ((ps->content = (char *)xmalloc(BLOCK)) == NULL) {
		return (B_FALSE);
	}

	(void) memset(ps->content, 0, BLOCK);

	ps->data.cur_pos = 0UL;
	ps->data.content_length = 0UL;
	ps->url.https = B_FALSE;
	ps->uniqfile = NULL;
	ps->link = NULL;
	ps->dwnld_dir = NULL;
	ps->spool = B_TRUE;
	ps->errstr = NULL;
	ps->keystore = NULL;

	return (B_TRUE);
}

/*
 * Name:		ck_downld_dir_space
 * Description:	Verify enough space exists in directory to hold file
 *
 * Arguments:	err - where to record any errors.
 *     		dwnld_dir - Directory to check available space in
 *		bytes_needed - How many bytes are need
 *
 * Returns :	B_TRUE - enough space exists in dwnld_dir to hold
 *		bytes_needed bytes, otherwise B_FALSE
 */
static boolean_t
ck_dwnld_dir_space(PKG_ERR *err, char *dwnld_dir, ulong_t bytes_needed)
{
	u_longlong_t bytes_avail;
	u_longlong_t block_pad;
	struct statvfs64 status;

	if (statvfs64(dwnld_dir, &status)) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_TMPDIR), dwnld_dir);
		return (B_FALSE);
	}

	block_pad = (status.f_frsize ? status.f_frsize : status.f_bsize);
	bytes_avail = status.f_bavail * block_pad;

	if ((((u_longlong_t)bytes_needed) + block_pad) > bytes_avail) {
		pkgerr_add(err, PKGERR_WEB, gettext(ERR_DISK_SPACE),
		    dwnld_dir,
		    (((u_longlong_t)bytes_needed) + block_pad) / 1024ULL,
		    bytes_avail / 1024ULL);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Description:
 *    This function returns a unique file name based on the parts of the
 *    URI. This is done to enable partially downloaded files to be resumed.
 * Arguments:
 *    dir - The directory that should contain the filename.
 *    last_modified - A string representing the date of last modification,
 *	used as part of generating unique name
 * Returns:
 *    A valid filename or NULL.
 */

static char *
get_unique_filename(char *dir, char *last_modified)
{
	char *buf, *buf2, *beg_str;
	int len;

	if ((buf = (char *)xmalloc(PATH_MAX)) == NULL) {
		return (NULL);
	}
	if ((buf2 = (char *)xmalloc(PATH_MAX)) == NULL) {
		return (NULL);
	}

	/* prepare strings for being cat'ed onto */
	buf[0] = buf2[0] = '\0';
	/*
	 * No validation of the path is done here. We just construct the path
	 * and it must be validated later
	 */

	if (dir) {
		if (((len = snprintf(buf2, PATH_MAX, "%s/", dir)) < 0) ||
		    (len >= PATH_MAX))
			return (NULL);
	} else {
		return (NULL);
	}

	if (ps->url.abspath)
		if (strlcat(buf, ps->url.abspath, PATH_MAX) >= PATH_MAX)
			return (NULL);
	if (ps->url.hport.hostname)
		if (isdigit((int)ps->url.hport.hostname[0])) {
			if (strlcat(buf, ps->url.hport.hostname, PATH_MAX)
					>= PATH_MAX)
				return (NULL);
		} else {
			if ((beg_str =
				get_startof_string(ps->url.hport.hostname, '.'))
					!= NULL)
				if (strlcat(buf, beg_str, PATH_MAX) >= PATH_MAX)
					return (NULL);
		}
	if (last_modified != NULL)
		if (strlcat(buf, last_modified, PATH_MAX) >= PATH_MAX)
			return (NULL);

	if ((buf = replace_token(buf, '/', '_')) != NULL) {
		if (strlcat(buf2, buf, PATH_MAX) >= PATH_MAX) {
			return (NULL);
		} else {
			if (buf) free(buf);
			return (buf2);
		}
	} else {
		if (buf) free(buf);
		if (buf2) free(buf2);
		return (NULL);
	}
}

/*
 * Description:
 *    Removes token(s) consisting of one character from any path.
 * Arguments:
 *    path  - The path to search for the token in.
 *    token - The token to search for
 * Returns:
 *    The path with all tokens removed or NULL.
 */
static char *
replace_token(char *path, char oldtoken, char newtoken)
{
	char *newpath, *p;

	if ((path == NULL) || (oldtoken == '\0') || (newtoken == '\0')) {
		return (NULL);
	}

	newpath = xstrdup(path);

	for (p = newpath; *p != '\0'; p++) {
		if (*p == oldtoken) {
			*p = newtoken;
		}
	}

	return (newpath);
}

/*
 * Name:        trim
 * Description: Trims whitespace from a string
 *              has been registered)
 * Scope:       private
 * Arguments:   string  - string to trim.  It is assumed
 *              this string is writable up to it's entire
 *              length.
 * Returns:     none
 */
static void
trim(char *str)
{
	int len, i;
	if (str == NULL) {
		return;
	}

	len = strlen(str);
	/* strip from front */
	while (isspace(*str)) {
		for (i = 0; i < len; i++) {
			str[i] = str[i+1];
		}
	}

	/* strip from back */
	len = strlen(str);
	while (isspace(str[len-1])) {
		len--;
	}
	str[len] = '\0';
}

/*
 * Description:
 *    Resolves double quotes
 * Arguments:
 *    str  - The string to resolve
 * Returns:
 *    None
 */
static void
dequote(char *str)
{
	char *cp;

	if ((str == NULL) || (str[0] != '"')) {
		/* no quotes */
		return;
	}

	/* remove first quote */
	memmove(str, str + 1, strlen(str) - 1);

	/*
	 * scan string looking for ending quote.
	 * escaped quotes like \" don't count
	 */
	cp = str;

	while (*cp != '\0') {
		switch (*cp) {
		case '\\':
			/* found an escaped character */
			/* make sure end of string is not '\' */
			if (*++cp != '\0') {
				cp++;
			}
			break;

		case '"':
			*cp = '\0';
			break;
		default:
			cp++;
		}
	}
}

/*
 * Name:		get_ENV_proxy
 * Description:	Retrieves setting of proxy env variable
 *
 * Arguments:	err - where to record any errors.
 *		proxy - where to store proxy
 *
 * Returns :	B_TRUE - http proxy was found and valid, stored in proxy
 *		B_FALSE - error, errors recorded in err
 */
static boolean_t
get_ENV_proxy(PKG_ERR *err, char **proxy)
{
	char *buf;

	if ((buf = getenv("HTTPPROXY")) != NULL) {
		if (!path_valid(buf)) {
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_ILL_ENV), "HTTPPROXY", buf);
			return (B_FALSE);
		} else {
			*proxy = buf;
			return (B_TRUE);
		}
	} else {
		/* try the other env variable */
		if ((buf = getenv("http_proxy")) != NULL) {
			if (!path_valid(buf)) {
				pkgerr_add(err, PKGERR_WEB,
				    gettext(ERR_ILL_ENV), "http_proxy", buf);
				return (B_FALSE);
			}
			if (!strneq(buf, "http://", 7)) {
				pkgerr_add(err, PKGERR_WEB,
				    gettext(ERR_ILL_ENV), "http_proxy", buf);
				return (B_FALSE);
			}

			/* skip over the http:// part of the proxy "url" */
			    *proxy = buf + 7;
			    return (B_TRUE);
		}
	}

	/* either the env variable(s) were set and valid, or not set */
	return (B_TRUE);
}

/*
 * Name:		get_ENV_proxyport
 * Description:	Retrieves setting of PROXYPORT env variable
 *
 * Arguments:	err - where to record any errors.
 *		port - where to store resulting port
 *
 * Returns :	B_TRUE - string found in PROXYPORT variable, converted
 *		to decimal integer, if it exists
 *		and is valid.  Or, PROXYPORT not set, port set to 1.
 *		B_FALSE - env variable set, but invalid
 *			(not a number for example)
 */
static boolean_t
get_ENV_proxyport(PKG_ERR *err, ushort_t *port)
{
	char *buf;
	ushort_t	newport;
	buf = getenv("HTTPPROXYPORT");
	if (buf != NULL) {
		if (!path_valid(buf)) {
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_ILL_ENV), "HTTPPROXYPORT", buf);
			return (B_FALSE);
		}
		if ((newport = atoi(buf)) == 0) {
			pkgerr_add(err, PKGERR_WEB,
			    gettext(ERR_ILL_ENV), "HTTPPROXYPORT", buf);
			return (B_FALSE);
		}
		*port = newport;
		return (B_TRUE);
	} else {
		*port = 1;
		return (B_TRUE);
	}
}

/*
 * Name:		remove_dwnld_file
 * Description:	Removes newly-downloaded file if completely downloaded.
 *
 * Arguments:	path - path to file to remove
 *
 * Returns :	B_TRUE - success, B_FALSE otherwise
 *		if it's '0' (not OK) we simply return it, since the
 *		verification operation has already determined that the
 *		cert is invalid.  if 'ok' is non-zero, then we do our
 *		checks, and return 0 or 1 based on if the cert is
 *		invalid or valid.
 */
static boolean_t
remove_dwnld_file(char *path)
{
	if (path && path != NULL) {
		/*
		 * Only remove the downloaded file if it has been completely
		 * downloaded, or is not eligible for spooling
		 */
		if ((!ps->spool) ||
		    (ps->data.cur_pos  >= ps->data.content_length)) {
			(void) unlink(path);
		}
	} else {
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Name:		condense_lastmodifided
 * Description:	generates a substring of a last-modified string,
 *		and removes colons.
 *
 * Arguments:	last_modified - string of the form
 *		"Wed, 23 Oct 2002 21:59:45 GMT"
 *
 * Returns :
 *		new string, consisting of hours/minutes/seconds only,
 *		sans any colons.
 */
char *
condense_lastmodified(char *last_modified)
{
	char *p, *p2;

	/*
	 * Last-Modified: Wed, 23 Oct 2002 21:59:45 GMT
	 * Strip the hours, minutes and seconds, without the ':'s, from
	 * the above string, void of the ':".
	 */

	if (last_modified == NULL)
		return (NULL);

	if ((p = xstrdup(last_modified)) == NULL)
		return (NULL);
	p2 = (strstr(p, ":") - 2);
	p2[8] = '\0';
	return (replace_token(p2, ':', '_'));
}

/*
 * Name:		backoff
 * Description:	sleeps for a certain # of seconds after a network
 *		failure.
 * Scope:	public
 * Arguments:	none
 * Returns:	none
 */
void
backoff()
{
	static boolean_t initted = B_FALSE;
	int backoff;
	long seed;

	if (!initted) {
		/* seed the rng */
		(void) _get_random_info(&seed, sizeof (seed));
		srand48(seed);
		initted = B_TRUE;
	}

	backoff = drand48() * (double)cur_backoff;
	(void) sleep(backoff);
	if (cur_backoff < MAX_BACKOFF) {
		/*
		 * increase maximum time we might wait
		 * next time so as to fall off over
		 * time.
		 */
		cur_backoff *= BACKOFF_FACTOR;
	}
}

/*
 * Name:		reset_backoff
 * Description:	notifies the backoff service that whatever was
 *		being backoff succeeded.
 * Scope:	public
 * Arguments:	none
 * Returns:	none
 */
void
reset_backoff()
{
	cur_backoff = MIN_BACKOFF;
}

/*
 * Name:	_get_random_info
 * Description:	generate an amount of random bits.  Currently
 *		only a small amount (a long long) can be
 *		generated at one time.
 * Scope:	private
 * Arguments:	buf	- [RO, *RW] (char *)
 *			  Buffer to copy bits into
 *		size	- amount to copy
 * Returns:	B_TRUE on success, B_FALSE otherwise.  The buffer is filled
 *		with the amount of bytes of random data specified.
 */
static boolean_t
_get_random_info(void *buf, int size)
{
	struct timeval tv;
	typedef struct {
		long low_time;
		long hostid;
	} randomness;
	randomness r;

	/* if the RANDOM file exists, use it */
	if (access(RANDOM, R_OK) == 0) {
		if ((RAND_load_file(RANDOM, 1024 * 1024)) > 0) {
			if (RAND_bytes((uchar_t *)buf, size) == 1) {
				/* success */
				return (B_TRUE);
			}
		}
	}

	/* couldn't use RANDOM file, so fallback to time of day and hostid */
	(void) gettimeofday(&tv, (struct timezone *)0);

	/* Wouldn't it be nice if we could hash these */
	r.low_time = tv.tv_usec;
	r.hostid = gethostid();

	if (sizeof (r) < size) {
		/*
		 * Can't copy correctly
		 */
		return (B_FALSE);
	}
	(void) memcpy(buf, &r, size);
	return (B_TRUE);
}

/*
 * Name:		pkg_passphrase_cb
 * Description:	Default callback that applications can use when
 *		a passphrase is needed.  This routine collects
 *		a passphrase from the user using the given
 *		passphrase retrieval method set with
 *		set_passphrase_passarg().  If the method
 *		indicates an interactive prompt, then the
 *		prompt set with set_passphrase_prompt()
 *		is displayed.
 *
 * Arguments:	buf	- Buffer to copy passphrase into
 *		size	- Max amount to copy to buf
 *		rw	- Whether this passphrase is needed
 *			to read something off disk, or
 *			write something to disk.  Applications
 *			typically want to ask twice when getting
 *			a passphrase for writing something.
 *		data	- application-specific data.  In this
 *			callback, data is a pointer to
 *			a keystore_passphrase_data structure.
 *
 * Returns:	Length of passphrase collected, or -1 on error.
 *		Errors recorded in 'err' object in the *data.
 */
int
pkg_passphrase_cb(char *buf, int size, int rw, void *data)
{
	BIO		*pwdbio = NULL;
	char		passphrase_copy[MAX_PHRASELEN + 1];
	PKG_ERR		*err;
	int		passlen;
	char		*ws;
	char		prompt_copy[MAX_VERIFY_MSGLEN];
	char		*passphrase;
	char		*arg;

	err = ((keystore_passphrase_data *)data)->err;

	if (passarg == NULL) {
		arg = "console";
	} else {
		arg = passarg;
	}

	/* default method of collecting password is by prompting */
	if (ci_streq(arg, "console")) {
		if ((passphrase = getpassphrase(prompt)) == NULL) {
			pkgerr_add(err, PKGERR_BADPASS,
			    gettext(MSG_NOPASS), arg);
			return (-1);
		}

		if (rw) {
			/*
			 * if the password is being supplied for
			 * writing something to disk, verify it first
			 */

			/* make a copy (getpassphrase overwrites) */
			strlcpy(passphrase_copy, passphrase,
			    MAX_PHRASELEN + 1);

			if (((passlen = snprintf(prompt_copy,
					MAX_VERIFY_MSGLEN, "%s: %s",
					gettext(MSG_PASSWD_AGAIN),
					prompt)) < 0) ||
			    (passlen >= (MAX_PHRASELEN + 1))) {
				pkgerr_add(err, PKGERR_BADPASS,
				    gettext(MSG_NOPASS), arg);
				return (-1);
			}

			if ((passphrase =
			    getpassphrase(prompt_copy)) == NULL) {
				pkgerr_add(err, PKGERR_BADPASS,
				    gettext(MSG_NOPASS), arg);
				return (-1);
			}

			if (!streq(passphrase_copy, passphrase)) {
				pkgerr_add(err, PKGERR_READ,
				    gettext(MSG_PASSWD_NOMATCH));
				return (-1);
			}
		}
	} else if (ci_strneq(arg, "pass:", 5)) {
		passphrase = arg + 5;
	} else if (ci_strneq(arg, "env:", 4)) {
		passphrase = getenv(arg + 4);
	} else if (ci_strneq(arg, "file:", 5)) {

		/* open file for reading */
		if ((pwdbio = BIO_new_file(arg + 5, "r")) == NULL) {
			pkgerr_add(err, PKGERR_EXIST,
			    gettext(MSG_PASSWD_FILE), arg + 5);
			return (-1);
		}

		/* read first line */
		if (((passlen = BIO_gets(pwdbio, buf, size)) < 1) ||
		    (passlen > size)) {
			pkgerr_add(err, PKGERR_READ, gettext(MSG_PASSWD_FILE),
			    arg + 5);
			return (-1);
		}
		BIO_free_all(pwdbio);
		pwdbio = NULL;

		if (passlen == size) {
			/*
			 * password was maximum length, so there is
			 * no null terminator. null-terminate it
			 */
			buf[size - 1] = '\0';
		}

		/* first newline found is end of passwd, so nuke it */
		if ((ws = strchr(buf, '\n')) != NULL) {
			*ws = '\0';
		}
		return (strlen(buf));
	} else {
		/* unrecognized passphrase */
		pkgerr_add(err, PKGERR_BADPASS,
		    gettext(MSG_BADPASSARG), arg);
		return (-1);
	}

	if (passphrase == NULL) {
		/* unable to collect passwd from given source */
		pkgerr_add(err, PKGERR_BADPASS,
		    gettext(MSG_NOPASS), arg);
		return (-1);
	}

	strlcpy(buf, passphrase, size);
	return (strlen(buf));
}
