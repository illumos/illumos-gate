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

#include <sys/types.h>
#include <sys/promif.h>
#include <sys/obpdefs.h>
#include <sys/bootvfs.h>
#include <sys/bootconf.h>
#include <netinet/in.h>
#include <sys/wanboot_impl.h>
#include <boot_http.h>
#include <aes.h>
#include <des3.h>
#include <cbc.h>
#include <hmac_sha1.h>
#include <sys/sha1.h>
#include <sys/sha1_consts.h>
#include <bootlog.h>
#include <parseURL.h>
#include <netboot_paths.h>
#include <netinet/inetutil.h>
#include <sys/salib.h>
#include <inet/mac.h>
#include <inet/ipv4.h>
#include <dhcp_impl.h>
#include <inet/dhcpv4.h>
#include <bootinfo.h>
#include <wanboot_conf.h>
#include "boot_plat.h"
#include "ramdisk.h"
#include "wbcli.h"

/*
 * Types of downloads
 */
#define	MINIINFO	"miniinfo"
#define	MINIROOT	"miniroot"
#define	WANBOOTFS	"wanbootfs"

#define	WANBOOT_RETRY_NOMAX	-1
#define	WANBOOT_RETRY_ROOT_MAX	50
#define	WANBOOT_RETRY_MAX	5
#define	WANBOOT_RETRY_SECS	5
#define	WANBOOT_RETRY_MAX_SECS	30

/*
 * Our read requests should timeout after 25 seconds
 */
#define	SOCKET_READ_TIMEOUT	25

/*
 * Experimentation has shown that an 8K download buffer is optimal
 */
#define	HTTP_XFER_SIZE		8192
static char	buffer[HTTP_XFER_SIZE];

bc_handle_t	bc_handle;

extern int	determine_fstype_and_mountroot(char *);
extern uint64_t	get_ticks(void);

/*
 * The following is used to determine whether the certs and private key
 * files will be in PEM format or PKCS12 format.  'use_p12' is zero
 * to use PEM format, and 1 when PKCS12 format is to be used.  It is
 * done this way, as a global, so that it can be patched if needs be
 * using the OBP debugger.
 */
uint32_t	use_p12 = 1;

#define	CONTENT_LENGTH		"Content-Length"

#define	NONCELEN	(2 * HMAC_DIGEST_LEN) /* two hex nibbles/byte */
#define	WANBOOTFS_NONCE_FILE	"/nonce"

static char nonce[NONCELEN + 1];

enum URLtype {
	URLtype_wanbootfs = 0,
	URLtype_miniroot = 1
};

static char *URLtoCGIcontent[] = {
	"bootfs",
	"rootfs"
};
#define	CGIcontent(urltype)	URLtoCGIcontent[urltype]

/* Encryption algorithms */
typedef enum {
	ENCR_NONE,
	ENCR_3DES,
	ENCR_AES
} encr_type_t;

/* Hash algorithms */
typedef enum {
	HASH_NONE,
	HASH_HMAC_SHA1
} hash_type_t;

/*
 * Keys ...
 */
static encr_type_t	encr_type = ENCR_NONE;
static unsigned char	*g_encr_key = NULL;

static hash_type_t	hash_type = HASH_NONE;
static unsigned char	*g_hash_key = NULL;

void
print_errors(const char *func, http_handle_t handle)
{
	char const *msg;
	ulong_t err;
	uint_t src;

	while ((err = http_get_lasterr(handle, &src)) != 0) {
		msg = http_errorstr(src, err);
		bootlog("wanboot", BOOTLOG_ALERT,
		    "%s: errsrc %u, err %lu (0x%lx)", func, src, err, err);
		bootlog("wanboot", BOOTLOG_ALERT, "%s", msg);
	}
}

/*
 * This routine is called by a consumer to determine whether or not a
 * retry should be attempted. If a retry is in order (depends upon the
 * 'retry_cnt' and 'retry_max' arguments), then this routine will print a
 * message indicating this is the case and will determine an appropriate
 * "sleep" time before retrying. The "sleep" time will depend upon the
 * 'retry_cnt' and will max out at WANBOOT_RETRY_MAX_SECS.
 *
 * Returns:
 *	 B_TRUE  = retry is in order
 *	 B_FALSE = retry limit exceeded
 */
boolean_t
wanboot_retry(int retry_cnt, int retry_max)
{
	unsigned int seconds;

	if (retry_max == WANBOOT_RETRY_NOMAX || retry_cnt <= retry_max) {
		seconds = WANBOOT_RETRY_SECS * retry_cnt;
		if (seconds > WANBOOT_RETRY_MAX_SECS) {
			seconds = WANBOOT_RETRY_MAX_SECS;
		}
		bootlog("wanboot", BOOTLOG_INFO,
		    "Will retry in %d seconds ...", seconds);
		(void) sleep(seconds);
		return (B_TRUE);
	} else {
		bootlog("wanboot", BOOTLOG_INFO,
		    "Maximum retries exceeded.");
		return (B_FALSE);
	}
}

/*
 * Determine which encryption algorithm the client is configured to use.
 * WAN boot determines which key to use by order of priority.  That is
 * multiple encryption keys may exist in the PROM, but the first one found
 * (while searching in a preferred order) is the one that will be used.
 */
static void
init_encryption(void)
{
	static unsigned char	key[WANBOOT_MAXKEYLEN];
	size_t			len = sizeof (key);

	if (bootinfo_get(BI_AES_KEY, (char *)&key, &len, NULL) ==
	    BI_E_SUCCESS) {
		encr_type = ENCR_AES;
		g_encr_key = key;
	} else if (bootinfo_get(BI_3DES_KEY, (char *)&key, &len, NULL) ==
	    BI_E_SUCCESS) {
		encr_type = ENCR_3DES;
		g_encr_key = key;
	}
}

/*
 * Determine whether the client is configured to use hashing.
 */
static void
init_hashing(void)
{
	static unsigned char	key[WANBOOT_HMAC_KEY_SIZE];
	size_t			len = sizeof (key);

	if (bootinfo_get(BI_SHA1_KEY, (char *)&key, &len, NULL) ==
	    BI_E_SUCCESS) {
		hash_type = HASH_HMAC_SHA1;
		g_hash_key = key;
	}
}

/*
 * Read some CPU-specific rapidly-varying data (assumed to be of length
 * sizeof (hrtime_t) in the non-SPARC case), and digestify it to further
 * randomize the output.
 */
char *
generate_nonce(void)
{
	uint64_t	t;
	SHA1_CTX	c;
	unsigned char	digest[HMAC_DIGEST_LEN];
	uint_t		nlen = sizeof (nonce);

	int		err;

	/*
	 * Read SPARC %tick register or x86 TSC
	 */
	t = get_ticks();
	SHA1Init(&c);
	SHA1Update(&c, (const uint8_t *)&t, sizeof (t));
	SHA1Final(digest, &c);

	err = octet_to_hexascii(digest, sizeof (digest), nonce, &nlen);
	if (err != 0) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "cannot convert nonce to ASCII: error %d", err);
		return (NULL);
	}
	nonce[NONCELEN] = '\0';
	return (nonce);
}

/*
 * Given a server URL, builds a URL to request one of the wanboot
 * datastreams.
 *
 * Returns:
 *	-1 = Non-recoverable error
 *	 0 = Success
 */
static int
build_request_url(url_t *req_url, enum URLtype ut, const url_t *server_url)
{
	char		clid[WB_MAX_CID_LEN];
	size_t		clen;
	char		wid[WB_MAX_CID_LEN * 2 + 1];
	uint_t		wlen;
	struct in_addr	ip;
	struct in_addr	mask;
	char		*netstr;
	char		*ppath;
	size_t		plen;
	const char	reqstr[] = "/?CONTENT=%s&IP=%s&CID=%s";

	/*
	 * Initialize the request
	 */
	*req_url = *server_url;

	/*
	 * Build the network number string
	 */
	ipv4_getipaddr(&ip);
	ipv4_getnetmask(&mask);
	ip.s_addr = ip.s_addr & mask.s_addr;
	netstr = inet_ntoa(ip);

	/*
	 * Get the wan id
	 */
	clen = sizeof (clid);
	if (bootinfo_get(BI_CLIENT_ID, clid, &clen, NULL) != BI_E_SUCCESS) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "Cannot retrieve the client ID");
		return (-1);
	}
	wlen = sizeof (wid);
	(void) octet_to_hexascii(clid, clen, wid, &wlen);

	/*
	 * Build the request, making sure that the length of the
	 * constructed URL falls within the supported maximum.
	 */
	plen = strlen(req_url->abspath);
	ppath = req_url->abspath + plen;
	if (snprintf(ppath, URL_MAX_PATHLEN - plen, reqstr,
	    CGIcontent(ut), netstr, wid) >= URL_MAX_PATHLEN - plen) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "The URL path length of the %s request is greater than "
		    "the maximum of %d", CGIcontent(ut), URL_MAX_PATHLEN);
		return (-1);
	}

	/*
	 * If the URL type requires a nonce, then supply it.
	 * It will be returned in the reply to detect attempted
	 * replays.
	 */
	if (ut == URLtype_wanbootfs) {
		char	*n = generate_nonce();

		if (n != NULL) {
			plen += strlen("&NONCE=") + NONCELEN;
			if (plen > URL_MAX_PATHLEN)
				return (-1);
			(void) strcat(req_url->abspath, "&NONCE=");
			(void) strcat(req_url->abspath, n);
		}
	}

	return (0);
}

/*
 * This routine reads data from an HTTP connection into a buffer.
 *
 * Returns:
 *	 0 = Success
 *	 1 = HTTP download error
 */
static int
read_bytes(http_handle_t handle, char *buffer, size_t cnt)
{
	int len;
	size_t i;

	for (i = 0; i < cnt; i += len) {
		len = http_read_body(handle, &buffer[i], cnt - i);
		if (len <= 0) {
			print_errors("http_read_body", handle);
			return (1);
		}
	}
	return (0);
}

/*
 * This routine compares two hash digests, one computed by the server and
 * the other computed by the client to verify that a transmitted message
 * was received without corruption.
 *
 * Notes:
 *	The client only computes a digest if it is configured with a
 *	hash key. If it is not, then the server should not have a hash
 *	key for the client either and therefore should have sent a
 *	zero filled digest.
 *
 * Returns:
 *	 B_TRUE  = digest was verified
 *	 B_FALSE = digest did not verify
 */
static boolean_t
verify_digests(const char *what, unsigned char *cdigest, unsigned char *sdigest)
{
	static char	null_digest[HMAC_DIGEST_LEN];

	if (bcmp(sdigest, cdigest, HMAC_DIGEST_LEN) != 0) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "%s: invalid hash digest", what);
		bootlog("wanboot", BOOTLOG_CRIT,
		    "This may signify a client/server key mismatch");
		if (bcmp(sdigest, null_digest, HMAC_DIGEST_LEN) == 0) {
			bootlog("wanboot", BOOTLOG_CRIT,
			    "(client has key but wrong signature_type?)");
		} else if (bcmp(cdigest, null_digest, HMAC_DIGEST_LEN) == 0) {
			bootlog("wanboot", BOOTLOG_CRIT,
			    "(signature_type specified but no client key?)");
		}
		bootlog("wanboot", BOOTLOG_CRIT,
		    "or possible corruption of the image in transit");
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * This routine reads the part of a multipart message that contains a
 * hash digest. Errors in reading the digest are differentiated from
 * other kinds of errors so that the caller can decide whether or
 * not a retry is worthwhile.
 *
 * Note:
 *	The hash digest can either be an HMAC digest or it can be
 *	a zero length message (representing no hash digest).
 *
 * Returns:
 *	-1 = Non-recoverable error
 *	 0 = Success
 *	 1 = HTTP download error
 */
static int
read_digest(const char *what, http_handle_t handle, unsigned char *sdigest)
{
	char *lenstr;
	size_t digest_size;

	/*
	 * Process the HMAC digest header.
	 */
	if (http_process_part_headers(handle, NULL) != 0) {
		print_errors("http_process_part_headers", handle);
		return (1);
	}
	lenstr = http_get_header_value(handle, CONTENT_LENGTH);
	if (lenstr == NULL) {
		bootlog("wanboot", BOOTLOG_ALERT,
		    "%s: error getting digest length", what);
		return (1);
	}
	digest_size = (size_t)strtol(lenstr, NULL, 10);
	free(lenstr);

	/*
	 * Validate the HMAC digest length.
	 */
	if (digest_size != HMAC_DIGEST_LEN) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "%s: error validating response - invalid digest size",
		    what);
		return (-1);
	}

	/*
	 * Read the HMAC digest.
	 */
	if (read_bytes(handle, (char *)sdigest, digest_size) != 0) {
		bootlog("wanboot", BOOTLOG_ALERT,
		    "%s: error reading digest", what);
		return (1);
	}

	return (0);
}

/*
 * This routine reads data from an HTTP connection and writes the data
 * to a ramdisk. It also, optionally computes a hash digest of the processed
 * data. This routine may be called to continue writing a previously aborted
 * write. If this is the case, then the offset will be non-zero and the write
 * pointer into the ramdisk will be positioned correctly by the caller.
 *
 * Returns:
 *	-1 = Non-recoverable error
 *	 0 = Success
 *	 1 = HTTP download error
 */
static int
write_msg_to_ramdisk(const char *what, caddr_t addr, http_handle_t handle,
    size_t ramdisk_size, off_t *offset, SHA1_CTX *sha)
{
	int len;
	long nleft;
	static int bootlog_message_interval;
	static int bootlog_progress;
	int ret;

	/*
	 * Read the data and write it to the ramdisk.
	 */
	if (*offset == 0) {
		bootlog_progress = 0;
		bootlog_message_interval = ramdisk_size / sizeof (buffer);
		if (bootlog_message_interval < 500)
			bootlog_message_interval /= 5;
		else
			bootlog_message_interval /= 50;

		bootlog("wanboot", BOOTLOG_VERBOSE,
		    "Reading %s file system (%ld kB)",
		    what, ramdisk_size / 1024);
	} else {
		bootlog("wanboot", BOOTLOG_VERBOSE,
		    "Continuing read of %s file system (%ld kB)",
		    what, ramdisk_size / 1024);
	}
	for (ret = 0; ret == 0 && *offset < ramdisk_size;
	    *offset += len, addr += len) {
		nleft = ramdisk_size - *offset;

		if (nleft > sizeof (buffer))
			nleft = sizeof (buffer);

		len = http_read_body(handle, addr, nleft);
		if (len <= 0) {
			print_errors("http_read_body", handle);
			/*
			 * In the case of a partial failure, http_read_body()
			 * returns into 'len', 1 - the number of bytes read.
			 * So, a -65 means 64 bytes read and an error occurred.
			 */
			if (len != 0) {
				len = -(len + 1);
			}
			ret = 1;
		}
		if (sha != NULL) {
			HMACUpdate(sha, (uchar_t *)addr, (size_t)len);
		}
		if (bootlog_progress == bootlog_message_interval) {
			bootlog("wanboot", BOOTLOG_PROGRESS,
			    "%s: Read %ld of %ld kB (%ld%%)", what,
			    *offset / 1024, ramdisk_size / 1024,
			    *offset * 100 / ramdisk_size);
			bootlog_progress = 0;
		} else {
			bootlog_progress++;
		}
	}
	if (ret == 0) {
		bootlog("wanboot", BOOTLOG_PROGRESS,
		    "%s: Read %ld of %ld kB (%ld%%)", what,
		    *offset / 1024, ramdisk_size / 1024,
		    *offset * 100 / ramdisk_size);
		bootlog("wanboot", BOOTLOG_INFO, "%s: Download complete", what);
	}
	return (ret);
}

/*
 * This routine is called with a bootinfo parameter name.  If the parameter
 * has a value it should be a URL, and this will be used to initialize the
 * http_url structure.
 *
 * Returns:
 *	-1 = Non-recoverable error
 *	 0 = Success
 *	 1 = DHCP option not set
 */
static int
get_url(char *name, url_t *url)
{
	char	buf[URL_MAX_STRLEN];
	size_t	len;
	int	ret;

	bzero(buf, sizeof (buf));
	len = sizeof (buf) - 1;
	if (bootinfo_get(name, buf, &len, NULL) != BI_E_SUCCESS || len == 0) {
		return (1);
	}

	/*
	 * Parse the URL.
	 */
	ret = url_parse(buf, url);
	if (ret != URL_PARSE_SUCCESS) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "Unable to parse URL %s", buf);
		return (-1);
	}

	return (0);
}

/*
 * This routine initiates an HTTP request and returns a handle so that
 * the caller can process the response.
 *
 * Notes:
 *	Requests may be either secure or not. If the request is secure, then
 *	this routine assumes that a wanboot file system exists and
 *	uses its contents to provide the HTTP library with the information
 *	that will be required by SSL.
 *
 *	In order to facilitate transmission retries, this routine supports
 *	range requests. A caller may request a range by providing a non-zero
 *	offset. In which case, a range request is made that ranges from the
 *	offet to the end of the file.
 *
 *	If the client is configured to use an HTTP proxy, then this routine
 *	will make the HTTP library aware of the proxy.
 *
 *	Any HTTP errors encountered in downloading or processing the message
 *	are not deemed unrecoverable errors. The caller can simply try the
 *	request once again.
 *
 * Returns:
 *	-1 = Non-recoverable error
 *	 0 = Success
 *	 1 = HTTP download error
 */
static int
establish_http_connection(const char *what, http_handle_t *handlep,
    url_t *url, offset_t offset)
{
	static boolean_t	is_auth_file_init = B_FALSE;
	static boolean_t	is_proxy_init = B_FALSE;
	static boolean_t	proxy_exists = B_FALSE;
	static url_hport_t	proxy_hp;
	http_respinfo_t		*resp;
	char			buf[URL_MAX_STRLEN];
	size_t			len = sizeof (buf) - 1;
	int			ret;

	/* Check for HTTP proxy */
	if (!is_proxy_init &&
	    bootinfo_get(BI_HTTP_PROXY, buf, &len, NULL) == BI_E_SUCCESS &&
	    strlen(buf) > 0) {
		/*
		 * Parse the hostport.
		 */
		ret = url_parse_hostport(buf, &proxy_hp, URL_DFLT_PROXY_PORT);
		if (ret == URL_PARSE_SUCCESS) {
			proxy_exists = B_TRUE;
		} else {
			bootlog("wanboot", BOOTLOG_CRIT,
			    "%s is not set to a valid hostport value",
			    BI_HTTP_PROXY);
			return (-1);
		}
		is_proxy_init = B_TRUE;
	}

	http_set_p12_format(use_p12);

	/*
	 * Initialize the handle that will be used for the request.
	 */
	*handlep = http_srv_init(url);
	if (*handlep == NULL) {
		print_errors("http_srv_init", NULL);
		return (-1);
	}

	/*
	 * Is the request a secure one? If it is, then we need to do further
	 * setup. Search the wanboot file system for files that will be
	 * needed by SSL.
	 */
	if (url->https) {
		char		*cas;
		boolean_t	client_authentication = B_FALSE;

		if (http_set_random_file(*handlep, "/dev/urandom") < 0) {
			print_errors("http_set_random_file", *handlep);
			(void) http_srv_close(*handlep);
			return (-1);
		}

		/*
		 * We only need to initialize the CA once as it is not handle
		 * specific.
		 */
		if (!is_auth_file_init) {
			if (http_set_certificate_authority_file(NB_CA_CERT_PATH)
			    < 0) {
				print_errors(
				    "http_set_certificate_authority_file",
				    *handlep);
				(void) http_srv_close(*handlep);
				return (-1);
			}

			is_auth_file_init = B_TRUE;
		}

		/*
		 * The client certificate and key will not exist unless
		 * client authentication has been configured. If it is
		 * configured then the webserver will have added these
		 * files to the wanboot file system and the HTTP library
		 * needs to be made aware of their existence.
		 */
		if ((cas = bootconf_get(&bc_handle,
		    BC_CLIENT_AUTHENTICATION)) != NULL &&
		    strcmp(cas, "yes") == 0) {
			client_authentication = B_TRUE;

			if (http_set_client_certificate_file(*handlep,
			    NB_CLIENT_CERT_PATH) < 0) {
				print_errors("http_set_client_certificate_file",
				    *handlep);
				(void) http_srv_close(*handlep);
				return (-1);
			}

			if (http_set_private_key_file(*handlep,
			    NB_CLIENT_KEY_PATH) < 0) {
				print_errors("http_set_private_key_file",
				    *handlep);
				(void) http_srv_close(*handlep);
				return (-1);
			}
		}

		/*
		 * We do not really need to set this unless client
		 * authentication is configured or unless pkcs12 files
		 * are used.
		 */
		if ((client_authentication || use_p12) &&
		    http_set_password(*handlep, WANBOOT_PASSPHRASE) < 0) {
			print_errors("http_set_password", *handlep);
			(void) http_srv_close(*handlep);
			return (-1);
		}
	}

	/*
	 * If the client is using a proxy, tell the library.
	 */
	if (proxy_exists) {
		if (http_set_proxy(*handlep, &proxy_hp) != 0) {
			print_errors("http_set_proxy", *handlep);
			(void) http_srv_close(*handlep);
			return (-1);
		}
	}

	(void) http_set_socket_read_timeout(*handlep, SOCKET_READ_TIMEOUT);

	/*
	 * Ok, connect to the webserver.
	 */
	if (http_srv_connect(*handlep) == -1) {
		print_errors("http_srv_connect", *handlep);
		(void) http_srv_close(*handlep);
		return (1);
	}

	/*
	 * If the offset is 0, then we assume that we want the entire
	 * message. If the offset is not 0, then we assume that we are
	 * retrying a previously interrupted transfer and thus we make
	 * a range request.
	 */
	if (offset == 0) {
		if ((ret = http_get_request(*handlep, url->abspath)) == 0) {
			bootlog("wanboot", BOOTLOG_VERBOSE,
			    "%s: http_get_request: sent", what);
		} else {
			print_errors("http_get_request", *handlep);
			(void) http_srv_close(*handlep);
			return (1);
		}
	} else {
		if ((ret = http_get_range_request(*handlep, url->abspath,
		    offset, 0)) == 0) {
			bootlog("wanboot", BOOTLOG_VERBOSE,
			    "%s: http_get_range_request: sent", what);
		} else {
			print_errors("http_get_range_request", *handlep);
			(void) http_srv_close(*handlep);
			return (1);
		}
	}

	/*
	 * Tell the library to read in the response headers.
	 */
	ret = http_process_headers(*handlep, &resp);
	if (ret == -1) {
		print_errors("http_process_headers", *handlep);
		(void) http_srv_close(*handlep);
		return (1);
	}

	/*
	 * Check for a valid response code.
	 */
	if ((offset == 0 && resp->code != 200) ||
	    (offset != 0 && resp->code != 206)) {
		bootlog("wanboot", BOOTLOG_ALERT,
		    "%s: Request returned code %d", what, resp->code);
		if (resp->statusmsg != NULL && resp->statusmsg[0] != '\0')
			bootlog("wanboot", BOOTLOG_ALERT,
			    "%s", resp->statusmsg);
		http_free_respinfo(resp);
		(void) http_srv_close(*handlep);
		return (1);
	}
	http_free_respinfo(resp);

	/*
	 * Success.
	 */
	return (0);
}

/*
 * This routine is called by get_miniinfo() to receive the reply
 * to the request for the miniroot metadata. The reply is a two
 * part multipart message. The first part of the message contains
 * the miniroot file size. The second part of the message contains
 * a hash digest of the miniroot as computed by the server. This
 * routine receives both message parts and returns them to the caller.
 *
 * Notes:
 *	If the miniroot is going to be downloaded securely or if the
 *	the server has no hash key for the client, then the hash digest
 *	downloaded contains all zeros.
 *
 *	Any HTTP errors encountered in downloading or processing the message
 *	are not deemed unrecoverable errors. That is, get_miniinfo()
 *	tries re-requesting the message and tries processing it again.
 *
 * Returns:
 *	-1 = Non-recoverable error
 *	 0 = Success
 *	 1 = HTTP download error
 */
static int
process_miniinfo(http_handle_t handle, size_t *mini_size,
    unsigned char *sdigest)
{
	char	*lenstr;
	size_t	cnt;

	/*
	 * Process the file size header.
	 */
	if (http_process_part_headers(handle, NULL) != 0) {
		print_errors("http_process_part_headers", handle);
		return (1);
	}
	lenstr = http_get_header_value(handle, CONTENT_LENGTH);
	if (lenstr == NULL) {
		bootlog("wanboot", BOOTLOG_ALERT, "%s: error getting length "
		    "of first part of multipart message", MINIINFO);
		return (1);
	}
	cnt = (size_t)strtol(lenstr, NULL, 10);
	free(lenstr);
	if (cnt == 0 || cnt >= sizeof (buffer)) {
		bootlog("wanboot", BOOTLOG_ALERT, "%s: length of first part "
		    "of multipart message not a legal size", MINIINFO);
		return (1);
	}

	if (read_bytes(handle, buffer, cnt) != 0) {
		bootlog("wanboot", BOOTLOG_ALERT,
		    "%s: error reading miniroot size", MINIINFO);
		return (1);
	}
	buffer[cnt] = '\0';

	*mini_size = (size_t)strtol(buffer, NULL, 10);
	if (*mini_size == 0) {
		bootlog("wanboot", BOOTLOG_ALERT, "%s: body of first part "
		    "of multipart message not a legal size", MINIINFO);
		return (1);
	}

	return (read_digest(MINIINFO, handle, sdigest));
}

/*
 * This routine is called by get_miniroot() to retrieve the miniroot
 * metadata (miniroot size and a hash digest). This routine sends an
 * HTTP GET request to the webserver to request the download of the
 * miniroot metadata and relies on process_miniinfo() to receive the
 * reply, process it and ultimately return to it the miniroot size and
 * the hash digest.
 *
 * Note:
 *	Any HTTP errors encountered in downloading or processing the message
 *	are not deemed unrecoverable errors. That is, get_miniinfo() should
 *	try re-requesting the message and try processing again.
 *
 * Returns:
 *	-1 = Non-recoverable error
 *	 0 = Success
 */
int
get_miniinfo(const url_t *server_url, size_t *mini_size,
    unsigned char *sdigest)
{
	http_handle_t	handle;
	url_t		req_url;
	int		retry_cnt = 0;
	int		retry_max = WANBOOT_RETRY_MAX;
	int		ret;

	/*
	 * Build the URL to request the miniroot info.
	 */
	if (build_request_url(&req_url, URLtype_miniroot, server_url) == -1) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "Can't build the URL to make the %s request",
		    CGIcontent(URLtype_miniroot));
		return (-1);
	}

	/*
	 * Go get the miniroot info. If we fail reading the
	 * response we re-request the info in its entirety.
	 */
	bootlog("wanboot", BOOTLOG_VERBOSE, "Downloading miniroot info");

	do {
		if ((ret = establish_http_connection(MINIINFO, &handle,
		    &req_url, 0)) < 0) {
			break;
		} else if (ret > 0) {
			if (wanboot_retry(++retry_cnt, retry_max)) {
				continue;
			} else {
				break;
			}
		}

		if ((ret = process_miniinfo(handle, mini_size,
		    sdigest)) > 0) {
			if (!wanboot_retry(++retry_cnt, retry_max)) {
				(void) http_srv_close(handle);
				break;
			}
		}

		(void) http_srv_close(handle);

	} while (ret > 0);

	/*
	 * Success.
	 */
	if (ret == 0) {
		bootlog("wanboot", BOOTLOG_VERBOSE,
		    "Miniroot info download successful");
		return (0);
	} else {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "Miniroot info download aborted");
		return (-1);
	}
}

/*
 * This routine is called by get_miniroot() to receive the reply to
 * the request for the miniroot download. The miniroot is written
 * to ramdisk as it is received and a hash digest is optionally computed
 * as it does so. The miniroot is downloaded as one large message.
 * Because the message is so large, this routine is prepared to deal
 * with errors in the middle of download. If an error occurs during
 * download, then this message processes all received data up to the
 * point of the error and returns to get_miniroot() an error signifying
 * that a download error has occurred. Presumably, get_miniroot()
 * re-requests the remaining part of the miniroot not yet processed and
 * calls this routine back to process the reply. When this routine
 * returns succesfully, it returns a devpath to the ramdisk and the
 * computed hash (if computed).
 *
 * Note:
 *	In order to facilitate reentry, the ramdisk is left open
 *	and the original miniroot_size and HMAC handle are kept
 *	static.
 *
 * Returns:
 *	-1 = Non-recoverable error
 *	 0 = Success
 *	 1 = HTTP download error
 */
static int
process_miniroot(http_handle_t handle, hash_type_t htype,
    size_t length, char **devpath, off_t *offset, unsigned char *cdigest)
{
	static SHA1_CTX	sha;
	static size_t	miniroot_size;
	static caddr_t	miniroot_vaddr = NULL;
	int		ret;

	if (miniroot_vaddr == NULL) {
		if (htype == HASH_HMAC_SHA1) {
			bootlog("wanboot", BOOTLOG_INFO,
			    "%s: Authentication will use HMAC-SHA1", MINIROOT);
			HMACInit(&sha, g_hash_key, WANBOOT_HMAC_KEY_SIZE);
		}

		miniroot_size = length;

		miniroot_vaddr = create_ramdisk(RD_ROOTFS, miniroot_size,
		    devpath);
	}

	miniroot_vaddr += *offset;

	if ((ret = write_msg_to_ramdisk(MINIROOT, miniroot_vaddr, handle,
	    miniroot_size, offset, (htype == HASH_NONE) ? NULL : &sha)) != 0) {
		return (ret);
	}

	if (htype != HASH_NONE) {
		HMACFinal(&sha, g_hash_key, WANBOOT_HMAC_KEY_SIZE, cdigest);
	}

	return (0);
}

/*
 * This routine retrieves the miniroot from the webserver. The miniroot
 * is retrieved in two steps. First a request is made to the server
 * to retrieve miniroot metadata (miniroot size and a hash digest).
 * The second request actually results in the download of the miniroot.
 *
 * This routine relies on get_miniinfo() to make and process
 * the request for the miniroot metadata and returns the
 * miniroot size and the hash digest of the miniroot as computed by
 * the server.
 *
 * If get_miniinfo() returns successfully, then this routine sends
 * an HTTP GET request to the webserver to request download of the
 * miniroot. This routine relies on process_miniroot() to receive
 * the reply, process it and ultimately return to it a device path to
 * a ramdisk containing the miniroot and a client computed hash digest.
 * This routine verifies that the client computed hash digest matches
 * the one retrieved by get_miniinfo().
 *
 * If an error occurs in the transfer of the miniroot from the server
 * to the client, then the client re-requests the download of the
 * miniroot using a range request and only requests the part of the
 * miniroot not previously downloaded and written to ramdisk. The
 * process_miniroot() routine has the intelligence to recognize that
 * it is processing a range request. Errors not related to the actual
 * message download are deemed unrecoverable.
 *
 * Note:
 *	If the client request for the miniroot is a secure request or
 *	if the server is not configured with a hash key for the client,
 *	then the hash digest downloaded from the server will contain
 *	all zeros. This routine verifies that the server and client are
 *	in-sync with respect to the need for hash verification.
 *
 * Returns:
 *	-1 = Non-recoverable error
 *	 0 = Success
 */
int
get_miniroot(char **devpath)
{
	http_handle_t	handle;
	unsigned char	cdigest[HMAC_DIGEST_LEN];
	unsigned char	sdigest[HMAC_DIGEST_LEN];
	char		*urlstr;
	url_t		server_url;
	size_t		mini_size;
	off_t		offset;
	int		plen;
	int		retry_cnt = 0;
	int		retry_max = WANBOOT_RETRY_ROOT_MAX;
	int		ret;

	/*
	 * Get the miniroot URL.
	 */
	if ((urlstr = bootconf_get(&bc_handle, BC_ROOT_SERVER)) == NULL) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "Missing root_server URL");
		return (-1);
	} else if (url_parse(urlstr, &server_url) != URL_PARSE_SUCCESS) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "Unable to parse URL %s", urlstr);
		return (-1);
	}

	/*
	 * We must get the miniroot info before we can request
	 * the miniroot itself.
	 */
	if (get_miniinfo(&server_url, &mini_size, sdigest) != 0) {
		return (-1);
	}

	plen = sizeof (server_url.abspath);
	if ((urlstr = bootconf_get(&bc_handle, BC_ROOT_FILE)) == NULL ||
	    strlcpy(server_url.abspath, urlstr, plen) >= plen) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "Cannot retrieve the miniroot path");
		return (-1);
	}

	/*
	 * Go get the miniroot. If we fail reading the response
	 * then we re-request only the range we have yet to read,
	 * unless the error was "unrecoverable" in which case we
	 * re-request the entire file system.
	 */
	bootlog("wanboot", BOOTLOG_VERBOSE, "Downloading miniroot");

	bzero(cdigest, sizeof (cdigest));
	offset = 0;
	do {
		if ((ret = establish_http_connection(MINIROOT, &handle,
		    &server_url, offset)) < 0) {
			break;
		} else if (ret > 0) {
			if (wanboot_retry(++retry_cnt, retry_max)) {
				continue;
			} else {
				break;
			}
		}

		if ((ret = process_miniroot(handle,
		    server_url.https ? HASH_NONE : hash_type,
		    mini_size, devpath, &offset, cdigest)) > 0) {
			if (!wanboot_retry(++retry_cnt, retry_max)) {
				(void) http_srv_close(handle);
				break;
			}
		}

		(void) http_srv_close(handle);

	} while (ret > 0);

	/*
	 * Validate the computed digest against the one received.
	 */
	if (ret != 0 || !verify_digests(MINIROOT, cdigest, sdigest)) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "Miniroot download aborted");
		return (-1);
	}

	bootlog("wanboot", BOOTLOG_VERBOSE, "Miniroot download successful");
	return (0);
}

/*
 * This routine is called to finish the decryption process.
 * Its purpose is to free the resources allocated by the
 * encryption init routines.
 */
static void
encr_fini(encr_type_t etype, void *eh)
{
	switch (etype) {
	case ENCR_3DES:
		des3_fini(eh);
		break;
	case ENCR_AES:
		aes_fini(eh);
		break;
	default:
		break;
	}
}

/*
 * This routine is called by process_wanbootfs() to decrypt the encrypted
 * file system from ramdisk in place.  The method of decryption
 * (algorithm) will have already been determined by process_wanbootfs()
 * and the cbc_handle passed to this routine will already have been
 * initialized appropriately.
 *
 * Returns:
 *	-1 = Non-recoverable error
 *	 0 = Success
 */
static int
decrypt_wanbootfs(caddr_t addr, cbc_handle_t *ch, uint8_t *iv,
    size_t wanbootfs_size)
{
	if (!cbc_decrypt(ch, (uint8_t *)addr, wanbootfs_size, iv)) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "%s: cbc decrypt error", WANBOOTFS);
		return (-1);
	}
	return (0);
}

/*
 * This routine is called by get_wanbootfs() to receive the reply to
 * the request for the wanboot file system. The reply is a multipart message.
 * The first part of the message is the file system (which may or may
 * not be encrypted).  If encrypted, then the first block of the message
 * part is the CBC IV value used by the server to encrypt the remaining
 * part of the message part and is used by the client to decrypt it. The
 * second message part is a hash digest of the first part (the file
 * system) as computed by the server. If no hash key is configured
 * for the client, then the hash digest simply contains all zeros. This
 * routine receives both message parts. The file system is written to ramdisk
 * as it is received and simultaneously computes a hash digest (if a hash
 * key exists). Once the entire part is received, if the file system is
 * encrypted, it is read from ramdisk, decrypted and rewritten back to
 * ramdisk. The server computed hash digest is then read and along with the
 * ramdisk device path and the client computed hash digest is returned to the
 * caller.
 *
 * Notes:
 *	In order to decrypt the file system and to compute the client
 *	hash digest, an encryption key and a hash key is retrieved from
 *	the PROM (or the wanboot interpreter). The non-existence of these
 *	keys has implications on how the message response is processed and
 *	it is assumed that the server is configured identically.
 *
 *	Any HTTP errors encountered in downloading or processing the message
 *	are not deemed unrecoverable errors. That is, get_wanbootfs() will
 *	try re-requesting the message and will try processing it again.
 *
 * Returns:
 *	-1 = Non-recoverable error
 *	 0 = Success
 *	 1 = HTTP download error
 */
static int
process_wanbootfs(http_handle_t handle, char **devpath,
    unsigned char *cdigest, unsigned char *sdigest)
{
	/* iv[] must be sized to store the largest possible encryption block */
	uint8_t		iv[WANBOOT_MAXBLOCKLEN];
	cbc_handle_t	ch;
	void		*eh;
	SHA1_CTX	sha;
	char		*lenstr;
	size_t		wanbootfs_size;
	size_t		block_size;
	off_t		offset;
	static caddr_t	bootfs_vaddr = NULL;
	int		ret;

	switch (hash_type) {
	case HASH_HMAC_SHA1:
		bootlog("wanboot", BOOTLOG_INFO,
		    "%s: Authentication will use HMAC-SHA1", WANBOOTFS);
		HMACInit(&sha, g_hash_key, WANBOOT_HMAC_KEY_SIZE);
		break;
	case HASH_NONE:
		break;
	default:
		bootlog("wanboot", BOOTLOG_CRIT,
		    "%s: unrecognized hash type", WANBOOTFS);
		return (-1);
	}

	switch (encr_type) {
	case ENCR_3DES:
		bootlog("wanboot",
		    BOOTLOG_INFO, "%s: Decryption will use 3DES", WANBOOTFS);
		if (des3_init(&eh) != 0) {
			return (-1);
		}
		block_size = DES3_BLOCK_SIZE;
		des3_key(eh, g_encr_key);
		cbc_makehandle(&ch, eh, DES3_KEY_SIZE, block_size,
		    DES3_IV_SIZE, des3_encrypt, des3_decrypt);

		break;
	case ENCR_AES:
		bootlog("wanboot",
		    BOOTLOG_INFO, "%s: Decryption will use AES", WANBOOTFS);
		if (aes_init(&eh) != 0) {
			return (-1);
		}
		block_size = AES_BLOCK_SIZE;
		aes_key(eh, g_encr_key, AES_128_KEY_SIZE);
		cbc_makehandle(&ch, eh, AES_128_KEY_SIZE, block_size,
		    AES_IV_SIZE, aes_encrypt, aes_decrypt);
		break;
	case ENCR_NONE:
		break;
	default:
		bootlog("wanboot", BOOTLOG_CRIT,
		    "%s: unrecognized encryption type", WANBOOTFS);
		return (-1);
	}

	/*
	 * Process the header.
	 */
	if (http_process_part_headers(handle, NULL) != 0) {
		print_errors("http_process_part_headers", handle);
		return (1);
	}
	lenstr = http_get_header_value(handle, CONTENT_LENGTH);
	if (lenstr == NULL) {
		bootlog("wanboot", BOOTLOG_ALERT, "%s: error getting length "
		    "of first part of multipart message", WANBOOTFS);
		return (1);
	}
	wanbootfs_size = (size_t)strtol(lenstr, NULL, 10);
	free(lenstr);
	if (wanbootfs_size == 0) {
		bootlog("wanboot", BOOTLOG_ALERT, "%s: length of first part "
		    "of multipart message not a legal size", WANBOOTFS);
		return (1);
	}

	/*
	 * If encrypted, then read the iv.
	 */
	if (encr_type != ENCR_NONE) {
		if (read_bytes(handle, (char *)iv, block_size) != 0) {
			bootlog("wanboot", BOOTLOG_ALERT,
			    "%s: error reading hash iv", WANBOOTFS);
			return (1);
		}
		wanbootfs_size -= block_size;
		if (hash_type != HASH_NONE) {
			HMACUpdate(&sha, (uchar_t *)iv, block_size);
		}
	}

	/*
	 * We can only create the ramdisk once. So, if we've
	 * already created it, then it means we've re-entered
	 * this routine from an earlier partial failure. Use
	 * the already existing ramdisk and seek back to the
	 * beginning of the file.
	 */
	if (bootfs_vaddr == NULL) {
		bootfs_vaddr = create_ramdisk(RD_BOOTFS, wanbootfs_size,
		    devpath);
	}

	offset = 0;

	if ((ret = write_msg_to_ramdisk(WANBOOTFS, bootfs_vaddr, handle,
	    wanbootfs_size, &offset, (hash_type == HASH_NONE) ? NULL : &sha))
	    != 0) {
		return (ret);
	}

	if (hash_type != HASH_NONE) {
		HMACFinal(&sha, g_hash_key, WANBOOT_HMAC_KEY_SIZE, cdigest);
	}

	/*
	 * If encrypted, then decrypt it.
	 */
	if (encr_type != ENCR_NONE) {
		ret = decrypt_wanbootfs(bootfs_vaddr, &ch, iv, wanbootfs_size);
		if (ret != 0) {
			encr_fini(encr_type, eh);
			return (-1);
		}
		encr_fini(encr_type, eh);
	}

	return (read_digest(WANBOOTFS, handle, sdigest));
}

/*
 * This routine sends an HTTP GET request to the webserver to
 * request the wanboot file system for the client. The server
 * will reply by sending a multipart message. This routine will rely
 * on process_wanbootfs() to receive the multipart message, process it
 * and ultimately return to it a device path to a ramdisk containing
 * the wanboot file system, a client computed hash digest and a
 * server computed hash digest. This routine will verify that the
 * client computed hash digest matches the one sent by the server. This
 * routine will also verify that the nonce received in the reply matches
 * the one sent in the request.
 *
 * If an error occurs in the transfer of the message from the server
 * to the client, then the client re-requests the download in its
 * entirety. Errors not related to the actual message download are
 * deemed unrecoverable.
 *
 * Returns:
 *	-1 = Non-recoverable error
 *	 0 = Success
 */
int
get_wanbootfs(const url_t *server_url)
{
	http_handle_t	handle;
	unsigned char	cdigest[HMAC_DIGEST_LEN];
	unsigned char	sdigest[HMAC_DIGEST_LEN];
	url_t		req_url;
	char		*devpath;
	int		ret;
	int		fd;
	char		buf[NONCELEN + 1];
	int		retry_cnt = 0;
	int		retry_max = WANBOOT_RETRY_MAX;

	/*
	 * Build the URL to request the wanboot file system. This URL
	 * will include the CGI script name and the IP, CID, and
	 * NONCE parameters.
	 */
	if (build_request_url(&req_url, URLtype_wanbootfs, server_url) == -1) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "Can't build the URL to make the %s request",
		    CGIcontent(URLtype_wanbootfs));
		return (-1);
	}

	/*
	 * Go get the wanboot file system. If we fail reading the
	 * response we re-request the entire file system.
	 */
	bootlog("wanboot", BOOTLOG_VERBOSE, "Downloading wanboot file system");

	bzero(cdigest, sizeof (cdigest));
	do {
		if ((ret = establish_http_connection(WANBOOTFS, &handle,
		    &req_url, 0)) < 0) {
			break;
		} else if (ret > 0) {
			if (wanboot_retry(++retry_cnt, retry_max)) {
				continue;
			} else {
				break;
			}
		}

		if ((ret = process_wanbootfs(handle, &devpath,
		    cdigest, sdigest)) > 0) {
			if (!wanboot_retry(++retry_cnt, retry_max)) {
				(void) http_srv_close(handle);
				break;
			}
		}

		(void) http_srv_close(handle);

	} while (ret > 0);

	/*
	 * Validate the computed digest against the one received.
	 */
	if (ret != 0 ||
	    !verify_digests(WANBOOTFS, cdigest, sdigest)) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "The wanboot file system download aborted");
		return (-1);
	}

	/*
	 * Mount the wanboot file system.
	 */
	if (determine_fstype_and_mountroot(devpath) != VFS_SUCCESS) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "Could not mount the wanboot filesystem.");
		bootlog("wanboot", BOOTLOG_CRIT,
		    "This may signify a client/server key mismatch");
		if (encr_type != ENCR_NONE) {
			bootlog("wanboot", BOOTLOG_CRIT,
			    "(client has key but wrong encryption_type?)");
		} else {
			bootlog("wanboot", BOOTLOG_CRIT,
			    "(encryption_type specified but no client key?)");
		}
		return (-1);
	}
	bootlog("wanboot", BOOTLOG_VERBOSE,
	    "The wanboot file system has been mounted");

	/*
	 * The wanboot file system should contain a nonce. Read it
	 * and compare it against the nonce sent in the request.
	 */
	if ((fd = open(WANBOOTFS_NONCE_FILE, O_RDONLY)) == -1) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "No nonce found in the wanboot file system");
		bootlog("wanboot", BOOTLOG_CRIT,
		    "The wanboot file system download aborted");
		return (-1);
	}

	if (read(fd, buf, NONCELEN) != NONCELEN ||
	    bcmp(nonce, buf, NONCELEN) != 0) {
		(void) close(fd);
		bootlog("wanboot", BOOTLOG_CRIT,
		    "Invalid nonce found in the wanboot file system");
		bootlog("wanboot", BOOTLOG_CRIT,
		    "The wanboot file system download aborted");
		return (-1);
	}

	(void) close(fd);

	bootlog("wanboot", BOOTLOG_VERBOSE,
	    "The wanboot file system download was successful");
	return (0);
}

static boolean_t
init_netdev(char *bpath)
{
	pnode_t		anode;
	int		proplen;
	char		netalias[OBP_MAXPATHLEN];
	static char	devpath[OBP_MAXPATHLEN];
	char		*p;

	bzero(netalias, sizeof (netalias));
	bzero(devpath, sizeof (devpath));

	/*
	 * Wanboot will either have loaded over the network (in which case
	 * bpath will name a network device), or from CD-ROM or disk.  In
	 * either case ensure that the 'net' alias corresponds to a network
	 * device, and that if a network boot was performed that it is
	 * identical to bpath.  This is so that the interface name can always
	 * be determined for CD-ROM or disk boots, and for manually-configured
	 * network boots.  The latter restriction may be relaxed in the future.
	 */
	anode = prom_alias_node();
	if ((proplen = prom_getproplen(anode, "net")) <= 0 ||
	    proplen > sizeof (netalias)) {
		goto error;
	}
	(void) prom_getprop(anode, "net", (caddr_t)netalias);

	/*
	 * Strip boot arguments from the net device to form
	 * the boot device path, returned as netdev_path.
	 */
	if (strlcpy(devpath, netalias, sizeof (devpath)) >= sizeof (devpath))
		goto error;
	if ((p = strchr(devpath, ':')) != NULL) {
		*p = '\0';
	}

	if (!is_netdev(netalias)) {
		bootlog("wanboot", BOOTLOG_CRIT, "'net'=%s\n", netalias);
		goto error;
	}

	if (is_netdev(bpath)) {
		/*
		 * If bpath is a network device path, then v2path
		 * will be a copy of this sans device arguments.
		 */
		if (strcmp(v2path, devpath) != 0) {
			bootlog("wanboot", BOOTLOG_CRIT,
			    "'net'=%s\n", netalias);
			bootlog("wanboot", BOOTLOG_CRIT,
			    "wanboot requires that the 'net' alias refers to ");
			bootlog("wanboot", BOOTLOG_CRIT,
			    "the network device path from which it loaded");
			return (B_FALSE);
		}
	} else {
		bpath = netalias;
	}

	/*
	 * Configure the network and return the network device.
	 */
	bootlog("wanboot", BOOTLOG_INFO, "configuring %s\n", bpath);
	netdev_path = devpath;
	mac_init(bpath);
	return (B_TRUE);

error:
	/*
	 * If we haven't established a device path for a network interface,
	 * then we're doomed.
	 */
	bootlog("wanboot", BOOTLOG_CRIT,
	    "No network device available for wanboot!");
	bootlog("wanboot", BOOTLOG_CRIT,
	    "(Ensure that the 'net' alias is set correctly)");
	return (B_FALSE);
}

/*
 * This implementation of bootprog() is used solely by wanboot.
 *
 * The basic algorithm is as follows:
 *
 * - The wanboot options (those specified using the "-o" flag) are processed,
 *   and if necessary the wanboot interpreter is invoked to collect other
 *   options.
 *
 * - The wanboot filesystem (containing certificates, wanboot.conf file, etc.)
 *   is then downloaded into the bootfs ramdisk, which is mounted for use
 *   by OpenSSL, access to wanboot.conf, etc.
 *
 * - The wanboot miniroot is downloaded over http/https into the rootfs
 *   ramdisk.  The bootfs filesystem is unmounted, and the rootfs filesystem
 *   is booted.
 */
/*ARGSUSED*/
int
bootprog(char *bpath, char *bargs, boolean_t user_specified_filename)
{
	char		*miniroot_path;
	url_t		server_url;
	int		ret;

	if (!init_netdev(bpath)) {
		return (-1);
	}

	if (!bootinfo_init()) {
		bootlog("wanboot", BOOTLOG_CRIT, "Cannot initialize bootinfo");
		return (-1);
	}

	/*
	 * Get default values from PROM, etc., process any boot arguments
	 * (specified with the "-o" option), and initialize the interface.
	 */
	if (!wanboot_init_interface(wanboot_arguments)) {
		return (-1);
	}

	/*
	 * Determine which encryption and hashing algorithms the client
	 * is configured to use.
	 */
	init_encryption();
	init_hashing();

	/*
	 * Get the bootserver value.  Should be of the form:
	 *	http://host[:port]/abspath.
	 */
	ret = get_url(BI_BOOTSERVER, &server_url);
	if (ret != 0) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "Unable to retrieve the bootserver URL");
		return (-1);
	}

	/*
	 * Get the wanboot file system and mount it. Contains metdata
	 * needed by wanboot.
	 */
	if (get_wanbootfs(&server_url) != 0) {
		return (-1);
	}

	/*
	 * Check that there is a valid wanboot.conf file in the wanboot
	 * file system.
	 */
	if (bootconf_init(&bc_handle, NULL) != BC_E_NOERROR) {
		bootlog("wanboot", BOOTLOG_CRIT,
		    "wanboot.conf error (code=%d)", bc_handle.bc_error_code);
		return (-1);
	}

	/*
	 * Set the time
	 */
	init_boot_time();

	/*
	 * Verify that URLs in wanboot.conf can be reached, etc.
	 */
	if (!wanboot_verify_config()) {
		return (-1);
	}

	/*
	 * Retrieve the miniroot.
	 */
	if (get_miniroot(&miniroot_path) != 0) {
		return (-1);
	}

	/*
	 * We don't need the wanboot file system mounted anymore and
	 * should unmount it so that we can mount the miniroot.
	 */
	(void) unmountroot();

	boot_ramdisk(RD_ROOTFS);

	return (0);
}
