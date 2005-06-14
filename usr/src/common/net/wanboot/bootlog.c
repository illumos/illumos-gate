/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * bootlog() - error notification and progress reporting for
 *            WAN boot components
 */

#include <sys/varargs.h>
#include <sys/types.h>
#include <sys/strlog.h>
#include <sys/wanboot_impl.h>
#include <errno.h>
#include <time.h>
#include <boot_http.h>
#include <stdio.h>
#include <parseURL.h>
#include <bootlog.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <libintl.h>
#include <netboot_paths.h>
#include <wanboot_conf.h>
#include <bootinfo.h>
#ifdef	_BOOT
#include <sys/bootdebug.h>
#endif

static struct code	pri_names[] = {
	"panic",	BOOTLOG_EMERG,
	"alert",	BOOTLOG_ALERT,
	"crit",		BOOTLOG_CRIT,
	"warn",		BOOTLOG_WARNING,
	"info",		BOOTLOG_INFO,
	"debug",	BOOTLOG_DEBUG,
	"verbose",	BOOTLOG_VERBOSE,
	"progress",	BOOTLOG_PROGRESS,
	"none",		NOPRI,
	NULL,		-1
};

typedef enum {
	BL_NO_TRANSPORT,
	BL_LOCAL_FILE,
	BL_CONSOLE,
	BL_HTTP,
	BL_HTTPS
} bl_transport_t;

typedef struct list_entry {
	char message[BOOTLOG_QS_MAX];
	struct list_entry *flink;
} list;

#define	BOOTLOG_RING_NELEM 512

static struct ringbuffer_t {
	int w_ptr;
	int r_ptr;
	list entries[BOOTLOG_RING_NELEM];
} ringbuffer;

static FILE *bl_filehandle = NULL;
static http_handle_t bl_httphandle = NULL;
static url_t bl_url;
static bl_transport_t bl_transport = BL_NO_TRANSPORT;

static bl_transport_t openbootlog(void);
static boolean_t setup_con(http_handle_t, boolean_t, boolean_t);
static char *url_encode(const char *);
static boolean_t sendmessage(bl_transport_t, char *, const char *,
    bootlog_severity_t, int);
static int ptr_incr(int ptr);
static int ptr_decr(int ptr);
static void rb_init(struct ringbuffer_t *);
static void rb_write(struct ringbuffer_t *, const char *);
static int rb_read(struct ringbuffer_t *, char *);

/*
 * Return a string representing the current time; not thread-safe.
 */
static const char *
gettime(void)
{
	static char	timebuf[sizeof ("Tue Jan 19 03:14:07 2038\n")];
	time_t 		curtime;

	if (time(&curtime) == 0)
		return ("<time unavailable>");

	(void) strlcpy(timebuf, ctime(&curtime), sizeof (timebuf));
	timebuf[19] = '\0';		/* truncate before "2038" above */
	return (timebuf);
}

/*
 * bootlog_common() -  Common routine used by bootlog() and
 *	bootlog_internal() to write a message comprising a message
 *	header and a message body to the appropriate transport.
 *	The message header comprises an ident string and a message
 *	severity.
 */
static void
bootlog_common(const char *ident, bootlog_severity_t severity, char *message)
{
	bl_transport_t	entry_transport;
	static int	blrecurs;
	static int	blretry;

	/*
	 * This function may be called recursively because the HTTP code
	 * is a bootlog consumer. The blrecurs variable is used to determine
	 * whether or not the invocation is recursive.
	 */
	blrecurs++;
	entry_transport = bl_transport;

	/*
	 * If this is the first bootlog call then setup the transport.
	 * We only do this in a non-recursive invocation as openbootlog()
	 * results in a recursive call for a HTTP or HTTPS transport.
	 */
	if (bl_transport == BL_NO_TRANSPORT && blrecurs == 1) {
		rb_init(&ringbuffer);
		bl_transport = openbootlog();
	}

	/*
	 * If we're not there already, try to move up a level.
	 * This is necessary because our consumer may have begun
	 * logging before it had enough information to initialize
	 * its HTTP or HTTPS transport. We've arbitrarily decided
	 * that we'll only check to see if we should move up, on
	 * every third (blretry) non-recursive invocation.
	 */
	if (blrecurs == 1 &&
	    !(bl_transport == BL_HTTPS || bl_transport == BL_HTTP)) {
		if (blretry > 3) {
			bl_transport = openbootlog();
			blretry = 0;
		} else
			blretry++;
	}

	if (entry_transport != bl_transport) {
		switch (bl_transport) {

		case BL_CONSOLE:
			(void) printf(
			    "%s wanboot info: WAN boot messages->console\n",
			    gettime());
			break;

		case BL_HTTP:
		case BL_HTTPS:
			(void) printf(
			    "%s wanboot info: WAN boot messages->%s:%u\n",
			    gettime(), bl_url.hport.hostname,
			    bl_url.hport.port);
			break;

		default:
			break;
		}
	}

	/*
	 * Failed attempts and recursively generated log messages are
	 * sent to the fallback transport.
	 */
	if (blrecurs > 1 || !sendmessage(bl_transport, message, ident,
	    severity, 0)) {
		/*
		 * Fallback to a log file if one exists, or the console
		 * as a last resort.  Note that bl_filehandle will always
		 * be NULL in standalone.
		 */
		(void) sendmessage(bl_filehandle != NULL ? BL_LOCAL_FILE :
		    BL_CONSOLE, message, ident, severity, 1);
	}
	blrecurs--;
}

/*
 * bootlog() - the exposed interface for logging boot messages.
 */
/* PRINTFLIKE3 */
void
bootlog(const char *ident, bootlog_severity_t severity, char *fmt, ...)
{
	char message[BOOTLOG_MSG_MAX_LEN];
	va_list adx;

	va_start(adx, fmt);
	(void) vsnprintf(message, BOOTLOG_MSG_MAX_LEN, fmt, adx);
	va_end(adx);

	bootlog_common(ident, severity, message);
}

/*
 * libbootlog() - an internal interface for logging boot
 *		messages.
 */
/* PRINTFLIKE2 */
void
libbootlog(bootlog_severity_t severity, char *fmt, ...)
{
	char message[BOOTLOG_MSG_MAX_LEN];
	va_list adx;

	va_start(adx, fmt);
	(void) vsnprintf(message, BOOTLOG_MSG_MAX_LEN,
	    dgettext(TEXT_DOMAIN, fmt), adx);
	va_end(adx);

	bootlog_common("libwanboot", severity, message);
}

static boolean_t
send_http(void)
{
	http_respinfo_t *resp = NULL;
	char buffer[BOOTLOG_MAX_URL + (BOOTLOG_QS_MAX * 3)];
	char ringmessage[BOOTLOG_QS_MAX];
	char *lenstr;
	size_t length;
	int retries;

	while ((rb_read(&ringbuffer, ringmessage) != -1)) {
		(void) snprintf(buffer, sizeof (buffer), "%s?%s",
		    bl_url.abspath, url_encode(ringmessage));

		for (retries = 0; retries < BOOTLOG_CONN_RETRIES; retries++) {
			if (retries > 0) {
				(void) http_srv_disconnect(bl_httphandle);
				if (http_srv_connect(bl_httphandle) != 0)
					continue;
			}

			if (http_get_request(bl_httphandle, buffer) != 0 ||
			    http_process_headers(bl_httphandle, &resp) != 0)
				continue;

			if (resp->code != 200) {
				http_free_respinfo(resp);
				continue;
			}

			http_free_respinfo(resp);
			lenstr = http_get_header_value(bl_httphandle,
			    "Content-Length");
			length = strtol(lenstr, NULL, 10);
			if (http_read_body(bl_httphandle, buffer, length) > 0)
				break;
		}

		/*
		 * The attempt to log the message failed. Back the
		 * read pointer up so that we'll try to log it again
		 * later.
		 */
		if (retries == BOOTLOG_CONN_RETRIES) {
			ringbuffer.r_ptr = ptr_decr(ringbuffer.r_ptr);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
sendmessage(bl_transport_t transport, char *message, const char *ident,
    bootlog_severity_t severity, int failure)
{
	static char *progtype = NULL;
	char ringmessage[BOOTLOG_QS_MAX];
	char hostname[MAXHOSTNAMELEN];
	uint32_t msgid;
	boolean_t ret;
	int i;

	/*
	 * In standalone, only log VERBOSE and DEBUG messages if the
	 * corresponding flag (-V or -d) has been passed to boot.
	 *
	 * Note that some bootlog() consumers impose additional constraints on
	 * printing these messages -- for instance, http_set_verbose() must be
	 * used before the HTTP code will call bootlog() with BOOTLOG_VERBOSE
	 * messages.
	 */
#ifdef	_BOOT
	if (severity == BOOTLOG_DEBUG && !(boothowto & RB_DEBUG))
		return (B_TRUE);
	if (severity == BOOTLOG_VERBOSE && !verbosemode)
		return (B_TRUE);
#endif

	for (i = 0; pri_names[i].c_val != NOPRI; i++) {
		if (severity == pri_names[i].c_val)
			break;
	}

	/*
	 * VERBOSE and DEBUG messages always go to the console
	 */
	if (transport != BL_CONSOLE &&
	    (severity == BOOTLOG_DEBUG || severity == BOOTLOG_VERBOSE)) {
		(void) printf("%s %s %s: %s\n", gettime(), ident,
		    pri_names[i].c_name, message);
	}

	STRLOG_MAKE_MSGID(message, msgid);
	(void) gethostname(hostname, sizeof (hostname));

	/*
	 * Note that in this case, "<time>" is a placeholder that will be used
	 * to fill in the actual time on the remote end.
	 */
	(void) snprintf(ringmessage, sizeof (ringmessage),
	    "<time> %s %s: [ID %u user.%s] %s", hostname, ident, msgid,
	    pri_names[i].c_name, message);

	/*
	 * Prevent duplicate messages from being inserted into
	 * the ring buffer.
	 */
	if (failure == 0) {
		rb_write(&ringbuffer, ringmessage);
	}

	switch (transport) {
	case BL_CONSOLE:
		/*
		 * PROGRESS messages update in-place on the console, as long
		 * as they are of the same 'progress type' (see below) --
		 * if not, reset the progress information.
		 */
		if (progtype != NULL && (severity != BOOTLOG_PROGRESS ||
		    strncmp(progtype, message, strlen(progtype)) != 0)) {
			(void) printf("\n");
			free(progtype);
			progtype = NULL;
		}

		(void) printf("%s %s %s: %s\r", gettime(), ident,
		    pri_names[i].c_name, message);

		if (severity != BOOTLOG_PROGRESS) {
			(void) printf("\n");
		} else if (progtype == NULL) {
			/*
			 * New progress message; save its "type" (the part
			 * of the message up to and including the first
			 * colon).  This should be made less clumsy in the
			 * future.
			 */
			progtype = strdup(message);
			if (progtype != NULL) {
				for (i = 0; progtype[i] != '\0'; i++) {
					if (progtype[i] == ':') {
						progtype[++i] = '\0';
						break;
					}
				}
			}
		}
		ret = B_TRUE;
		break;

	case BL_LOCAL_FILE:
		if (bl_filehandle == NULL)
			return (B_FALSE);

		(void) fprintf(bl_filehandle, "%s %s %s: [ID %u user.%s] %s\n",
		    gettime(), hostname, ident, msgid, pri_names[i].c_name,
		    message);
		ret = B_TRUE;
		break;

	case BL_HTTP:
	case BL_HTTPS:
		if (bl_httphandle == NULL)
			return (B_FALSE);
		ret = send_http();
		break;

	case BL_NO_TRANSPORT:
	default:
		ret = B_FALSE;
	}

	return (ret);
}

static bl_transport_t
openbootlog(void)
{
	static boolean_t	got_boot_logger = B_FALSE;
	static boolean_t	bl_url_valid = B_FALSE;
	static boolean_t	clientauth = B_FALSE;
	static bc_handle_t	bootconf_handle;
	bl_transport_t		transport;

	/*
	 * We try to use a logfile in userland since our consumer (install)
	 * needs complete control over the terminal.
	 */
#ifndef	_BOOT
	if (bl_filehandle == NULL)
		bl_filehandle = fopen("/var/log/bootlog", "a");
#endif
	transport = (bl_filehandle != NULL) ? BL_LOCAL_FILE : BL_CONSOLE;

	/*
	 * If we haven't already been able to access wanboot.conf for a
	 * boot_logger URL, see if we can now.
	 */
	if (!got_boot_logger &&
	    bootconf_init(&bootconf_handle, NULL) == BC_SUCCESS) {
		char	*urlstr;
		char	*cas;

		/*
		 * If there is a boot_logger, ensure that it's is a legal URL.
		 */
		if ((urlstr = bootconf_get(&bootconf_handle,
		    BC_BOOT_LOGGER)) != NULL &&
		    url_parse(urlstr, &bl_url) == URL_PARSE_SUCCESS) {
			bl_url_valid = B_TRUE;
		}

		/*
		 * If the boot_logger URL uses an HTTPS scheme, see if
		 * client authentication is specified.
		 */
		if (bl_url.https) {
			cas = bootconf_get(&bootconf_handle,
			    BC_CLIENT_AUTHENTICATION);
			if (cas != NULL) {
				clientauth = (strcmp(cas, BC_YES) == 0);
			}
		}

		bootconf_end(&bootconf_handle);

		/*
		 * Having now accessed wanboot.conf, remember not to come
		 * this way again; the value of boot_logger cannot change.
		 */
		got_boot_logger = B_TRUE;
	}

	/*
	 * If there is no legal boot_logger URL available, then we're done.
	 */
	if (!bl_url_valid) {
		return (transport);
	}

	/*
	 * If we don't already have a bl_httphandle, try to get one.
	 * If we fail, then we're done.
	 */
	if (bl_httphandle == NULL) {
		bl_httphandle = http_srv_init(&bl_url);
		if (bl_httphandle == NULL) {
			return (transport);
		}
	}

	/*
	 * If we succeed in setting up the connection,
	 * then we use the connection as our transport.
	 * Otherwise, we use the transport we've already
	 * determined above.
	 */
	if (setup_con(bl_httphandle, bl_url.https, clientauth)) {
		transport = bl_url.https ? BL_HTTPS : BL_HTTP;
	}

	return (transport);
}

static boolean_t
setup_con(http_handle_t handle, boolean_t https, boolean_t client_auth)
{
	static boolean_t	got_proxy = B_FALSE;
	static boolean_t	proxy_valid = B_FALSE;
	static url_hport_t	proxy;
	int			i;

	/*
	 * If an HTTPS scheme is specified, then check that time
	 * has been initialized.
	 * If time() returns a non-zero value, then we know
	 * that the boot file system has been mounted and that
	 * we have a trusted time.
	 */
	if (https && time(0) == 0)
		return (B_FALSE);

	if (!got_proxy && bootinfo_init()) {
		char	hpstr[URL_MAX_STRLEN];
		size_t	vallen = sizeof (hpstr);

		/*
		 * If there is a http-proxy, ensure that it's a legal host:port.
		 */
		if (bootinfo_get(BI_HTTP_PROXY, hpstr, &vallen, NULL) ==
		    BI_E_SUCCESS && vallen > 0) {
			hpstr[vallen] = '\0';
			if (url_parse_hostport(hpstr, &proxy,
			    URL_DFLT_PROXY_PORT) == URL_PARSE_SUCCESS) {
				proxy_valid = B_TRUE;
			}
		}

		got_proxy = B_TRUE;
	}
	if (proxy_valid && http_set_proxy(handle, &proxy) != 0)
		return (B_FALSE);

	(void) http_set_keepalive(handle, 1);
	(void) http_set_socket_read_timeout(handle, BOOTLOG_HTTP_TIMEOUT);

	/*
	 * If an HTTPS scheme is specified, then setup the necessary
	 * SSL context for the connection
	 */
	if (https) {
		if (http_set_random_file(handle, "/dev/urandom") == -1)
			return (B_FALSE);

		if (http_set_certificate_authority_file(NB_CA_CERT_PATH) < 0)
			return (B_FALSE);

		/*
		 * The client certificate and key will not exist unless
		 * client authentication has been configured. If it is
		 * configured then the webserver will have added these
		 * files to the wanboot file system and the HTTP library
		 * needs to be made aware of their existence.
		 */
		if (client_auth) {
			if (http_set_client_certificate_file(handle,
			    NB_CLIENT_CERT_PATH) < 0) {
				return (B_FALSE);
			}

			if (http_set_private_key_file(handle,
			    NB_CLIENT_KEY_PATH) < 0) {
				return (B_FALSE);
			}
		}

		if (http_set_password(handle, WANBOOT_PASSPHRASE) < 0)
			return (B_FALSE);
	}

	for (i = 0; i < BOOTLOG_CONN_RETRIES; i++) {
		if (http_srv_connect(handle) == 0)
			return (B_TRUE);

		(void) http_srv_disconnect(handle);
	}

	return (B_FALSE);
}

static char *
url_encode(const char *ibufp)
{
	int i;
	char c;
	unsigned char nibble;
	static char obuff[BOOTLOG_QS_MAX * 3];
	char *obufp = obuff;

	/*
	 * Encode special characters as outlined in RFC2396.
	 *
	 * Special characters are encoded as a triplets beginning
	 * with '%' followed by the two hexidecimal digits representing
	 * the octet code. The space character is special. It can be encoded
	 * simply as a '+'.
	 */
	while ((c = *ibufp++) != '\0') {
		/*
		 * Is the character one of the special characters
		 * that require encoding? If so append '%' to the output
		 * buffer follow that by the hexascii value.
		 */
		if (strchr("/?{}|^~[]`<>#%=\"\t", c) != NULL) {
			*obufp++ = '%';
			/*
			 * Compute the character's hex value and
			 * convert it to ASCII. That is two nibbles
			 * per character.
			 */
			for (i = 1; i >= 0; i--) {
				nibble = ((uchar_t)c >> (4 * i)) & 0x0f;
				/*
				 * If the hex digit is 0xa - 0xf, then
				 * compute its ASCII value by adding 0x37
				 * else 0x0 - 0x9 just add 0x30.
				 */
				if (nibble > 0x9)
					nibble += 0x37;
				else
					nibble += 0x30;
				*obufp++ = nibble;
			}
		/*
		 * The space character gets a special mapping.
		 */
		} else if (c == ' ') {
			*obufp++ = '+';

		/*
		 * Append the rest (sans any CR character)
		 */
		} else if (c != '\n') {
			*obufp++ = c;
		}
	}
	*obufp = '\0';
	return (obuff);
}

static void
rb_init(struct ringbuffer_t *buffer)
{
	int i;

	buffer->w_ptr = 0;
	buffer->r_ptr = 0;

	for (i = 0; i < BOOTLOG_RING_NELEM; i++)
		buffer->entries[i].message[0] = '\0';
}

static int
ptr_incr(int ptr)
{
	if (++ptr < BOOTLOG_RING_NELEM)
		return (ptr);
	else
		return (0);
}

static int
ptr_decr(int ptr)
{
	if (ptr == 0)
		return (BOOTLOG_RING_NELEM - 1);
	else
		return (--ptr);
}

static void
rb_write(struct ringbuffer_t *buffer, const char *buff)
{
	(void) strlcpy(buffer->entries[buffer->w_ptr].message, buff,
	    BOOTLOG_QS_MAX);
	buffer->w_ptr = ptr_incr(buffer->w_ptr);
	if (buffer->r_ptr == buffer->w_ptr)
		buffer->r_ptr = ptr_incr(buffer->r_ptr);
}

static int
rb_read(struct ringbuffer_t *buffer, char *buff)
{
	if (buffer->r_ptr != buffer->w_ptr) {
		(void) strlcpy(buff, buffer->entries[buffer->r_ptr].message,
		    BOOTLOG_QS_MAX);
		buffer->r_ptr = ptr_incr(buffer->r_ptr);
		return (0);
	}
	return (-1);
}
