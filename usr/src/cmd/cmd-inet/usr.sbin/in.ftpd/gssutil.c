/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * gssutil.c
 *
 * Utility routines for providing security related services to
 * the FTP server.  This code uses the GSSAPI (RFC 2743, 2744)
 * to provide a generic security layer to the application.  The
 * security mechanism providing the actual security functions
 * is abstracted from the application itself.  In the case of the FTP
 * server, the security mechanism is based on what the client chooses
 * to use when it makes the secure connection.  If the client's
 * choice of GSS mechanism is not supported by the FTP server, the
 * connection may be rejected or fall back to standard Unix/PAM
 * authentication.
 *
 * This code is primarily intended to work with clients who choose
 * the Kerberos V5 GSSAPI mechanism as their security service.
 */

#include "config.h"

#if defined(USE_GSS)
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdlib.h>
#include <signal.h>
#include <pwd.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <errno.h>
#include <sys/param.h>
#include <netdb.h>
#ifdef HAVE_SYS_SYSLOG_H
#include <sys/syslog.h>
#endif

/* CSTYLED */
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#include <syslog.h>
#endif

#ifdef HAVE_SYSINFO
#include <sys/systeminfo.h>
#endif

#include <arpa/ftp.h>

#include "gssutil.h"
#include "proto.h"

static char *gss_services[] = { "ftp", "host", 0 };

gss_info_t gss_info = {
	/* context */ GSS_C_NO_CONTEXT,
	/* mechoid */ GSS_C_NULL_OID,
	/* client */  NULL,
	/* display_name */ NULL,
	/* data_prot */  PROT_C,
	/* ctrl_prot */  PROT_C,
	/* authstate */  GSS_AUTH_NONE,
	/* want_creds */ 0,
	/* have_creds */ 0,
	/* must_auth  */ 0
};


extern char *cur_auth_type;
extern struct SOCKSTORAGE his_addr;
extern struct SOCKSTORAGE ctrl_addr;
extern int debug;

static char *radixN =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char pad = '=';

#define	DEF_GSSBUF_SIZE 2028
#define	DECODELEN(l)		(((3 * (l)) / 4) + 4)
#define	ENCODELEN(l)		(((4 * (l)) / 3) + 4)

typedef struct {
	char   *buf;
	size_t alloc_len;
	size_t len;  /* max length of buffer */
	size_t idx;  /* offset to beginning of read/write data */
	size_t clen;  /* length of the remaining, decrypted data from client */
}bufrec;

static bufrec obr = {NULL, 0, 0, 0, 0};
static bufrec ibr = {NULL, 0, 0, 0, 0};

static int looping_write(int fd, const char *buf, size_t len);
static int looping_read(int fd, char *buf, size_t len);
static int radix_encode(unsigned char *inbuf, unsigned char *outbuf,
			size_t len, int *outlen, int decode);
static char *radix_error(int e);
static void reply_gss_error(int code, OM_uint32 maj_stat,
			OM_uint32 min_stat, gss_OID mechoid, char *s);
static void cleanup_bufrec(bufrec *brec);
static int alloc_bufrec(bufrec *brec, size_t newsz);
static int sec_putbuf(int fd, unsigned char *buf, int len);
static int sec_getbytes(int fd, char *buf, int nbytes);

/*
 * Provide a routine so that ftpd can know the max amount to read
 */
size_t
gss_getinbufsz(void) {
	return (ibr.len);
}

/*
 * gss_adjust_buflen
 *
 * Called when the protection method changes so we can adjust the
 * "useable" length of our output buffer accordingly.
 */
void
gss_adjust_buflen()
{
	OM_uint32 maj_stat, min_stat, mlen;

	/*
	 * If we switched to CLEAR protection, we can use the entire buffer
	 */
	if (gss_info.data_prot == PROT_C) {
		obr.len = obr.alloc_len;
		return;
	}

	/*
	 * Otherwise, determine the maximum size that will allow for
	 * the GSSAPI overhead to fit into the buffer size.
	 */
	maj_stat = gss_wrap_size_limit(&min_stat, gss_info.context,
					(gss_info.data_prot == PROT_P),
					GSS_C_QOP_DEFAULT,
					(OM_uint32)obr.alloc_len, &mlen);
	if (maj_stat != GSS_S_COMPLETE) {
			reply_gss_error(535, maj_stat, min_stat,
					gss_info.mechoid,
					"GSSAPI fudge determination");
			return;
	}
	obr.len = mlen;

	if (debug)
		syslog(LOG_DEBUG, "GSSAPI alloc_len = %d len = %d",
		    obr.alloc_len, obr.len);
}

static int
looping_write(int fd, const char *buf, size_t len)
{
	int cc;
	register size_t wrlen = len;

	do {
		cc = write(fd, buf, wrlen);
		if (cc < 0) {
			if (errno == EINTR)
				continue;
			return (cc);
		} else {
			buf += cc;
			wrlen -= cc;
		}
	} while (wrlen > 0);

	return (len);
}

static int
looping_read(int fd, char *buf, size_t len)
{
	int cc;
	size_t len2 = 0;

	do {
		cc = read(fd, buf, len);
		if (cc < 0) {
			if (errno == EINTR)
				continue;
			return (cc);		 /* errno is already set */
		} else if (cc == 0) {
			return (len2);
		} else {
			buf += cc;
			len2 += cc;
			len -= cc;
		}
	} while (len > 0);
	return (len2);
}

static int
radix_encode(unsigned char *inbuf, unsigned char *outbuf,
		size_t buflen, int *outlen, int decode)
{
	register int i, j, D;
	char *p;
	unsigned char c;

	if (decode) {
		for (i = 0, j = 0; (j < buflen) &&
		    inbuf[i] && inbuf[i] != pad; i++) {
			if ((p = strchr(radixN, inbuf[i])) == NULL)
				return (1);
			D = p - radixN;
			switch (i&3) {
			case 0:
				outbuf[j] = D <<2;
				break;
			case 1:
				outbuf[j++] |= D >>4;
				outbuf[j] = (D&15)<<4;
				break;
			case 2:
				outbuf[j++] |= D >>2;
				outbuf[j] = (D&3)<<6;
				break;
			case 3:
				outbuf[j++] |= D;
			}
		}
		if (j == buflen && (inbuf[i] && inbuf[i] != pad)) {
			/* Oops, we ran out of space in the output buffer */
			return (4);
		}
		switch (i&3) {
		case 1:
			return (3);
		case 2: if (D&15)
				return (3);
			if (strcmp((char *)&inbuf[i], "=="))
				return (2);
			break;
		case 3: if (D&3)
				return (3);
			if (strcmp((char *)&inbuf[i], "="))
				return (2);
		}
		*outlen = j;
	} else {
		for (i = 0, j = 0; i < *outlen && j < buflen; i++)
			switch (i%3) {
			case 0:
				outbuf[j++] = radixN[inbuf[i]>>2];
				c = (inbuf[i]&3)<<4;
				break;
			case 1:
				outbuf[j++] = radixN[c|inbuf[i]>>4];
				c = (inbuf[i]&15)<<2;
				break;
			case 2:
				outbuf[j++] = radixN[c|inbuf[i]>>6];
				outbuf[j++] = radixN[inbuf[i]&63];
				c = 0;
		}
		if (j == buflen && i < *outlen) {
			/* output buffer is not big enough */
			return (4);
		}

		if (i%3) outbuf[j++] = radixN[c];
		switch (i%3) {
		case 1: outbuf[j++] = pad;
		case 2: outbuf[j++] = pad;
		}
		outbuf[*outlen = j] = '\0';
	}
	return (0);
}

static char *
radix_error(int e)
{
	switch (e) {
		case 0:  return ("Success");
		case 1:  return ("Bad character in encoding");
		case 2:  return ("Encoding not properly padded");
		case 3:  return ("Decoded # of bits not a multiple of 8");
		case 4:  return ("Buffer size error");
		default: return ("Unknown error");
	}
}

static void
reply_gss_error(int code, OM_uint32 maj_stat,
	OM_uint32 min_stat, gss_OID mechoid, char *s)
{
	/* a lot of work just to report the error */
	OM_uint32 gmaj_stat, gmin_stat;
	gss_buffer_desc msg;
	int msg_ctx;
	msg_ctx = 0;

	gmaj_stat = gss_display_status(&gmin_stat, maj_stat,
					GSS_C_GSS_CODE,
					mechoid,
					(OM_uint32 *)&msg_ctx, &msg);
	if (gmaj_stat == GSS_S_COMPLETE) {
		lreply(code, "GSSAPI error major: %s",
			(char *)msg.value);
			(void) gss_release_buffer(&gmin_stat, &msg);
	}

	gmaj_stat = gss_display_status(&gmin_stat, min_stat,
					GSS_C_MECH_CODE,
					mechoid,
					(OM_uint32 *)&msg_ctx, &msg);
	if (gmaj_stat == GSS_S_COMPLETE) {
		lreply(code, "GSSAPI error minor: %s", (char *)msg.value);
				(void) gss_release_buffer(&gmin_stat, &msg);
	}

	reply(code, "GSSAPI error: %s", s);
}


static void
log_status(char *msg,
	OM_uint32 status_code,
	int status_type)
{
	OM_uint32 message_context;
	gss_buffer_desc status_string;
	OM_uint32 maj_status;
	OM_uint32 min_status;

	/* From RFC2744: */
	message_context = 0;

	do {
		maj_status = gss_display_status(
			&min_status,
			status_code,
			status_type,
			GSS_C_NO_OID,
			&message_context,
			&status_string);

		if (maj_status == GSS_S_COMPLETE) {
			syslog(LOG_ERR,
			    "GSSAPI Error %s: %.*s\n",
			    msg ? msg : "<null>",
			    (int)status_string.length,
			    (char *)status_string.value);

			(void) gss_release_buffer(&min_status,
						&status_string);
		} else {
			syslog(LOG_ERR,
		"log_status internal error: gss_display_status failed");
			return;
		}
	} while (message_context != 0);

}

static void
log_gss_error(char *msg,
	    OM_uint32 maj_stat,
	    OM_uint32 min_stat)
{
	log_status(msg, maj_stat, GSS_C_GSS_CODE);
	log_status(msg, min_stat, GSS_C_MECH_CODE);
}


static void
log_gss_info(int priority,
	    char *luser,
	    char *remprinc,
	    gss_OID mechoid,
	    char *s)
{
	const char *mechStr = __gss_oid_to_mech(mechoid);

	syslog(priority,
	    "%s: local user=`%s', remote princ=`%s', mech=%s",
	    s ? s : "<null>",
	    luser ? luser : "<null>",
	    remprinc ? remprinc : "<unknown>",
	    mechStr ? mechStr : "<unknown>");
}

/*
 * gss_user
 *
 * Handle USER command after AUTH GSSAPI
 *
 * Check if the remote user can login to the local system w/out a passwd.
 * Use the Solaris (private) interface (__gss_userok) if possible, else do
 * a basic GSS-API compare.
 *
 * return 0 == BAD
 *        1 == OK
 */
int
gss_user(struct passwd *user_pw)
{
	int retval = 0;
	OM_uint32 status, minor;

#ifdef SOLARIS_GSS_USEROK

	int user_ok = 0;

	if (debug)
		log_gss_info(LOG_DEBUG,
			    user_pw->pw_name, gss_info.display_name,
			    gss_info.mechoid,
			    "gss_user: start (gss_userok)");

	/* gss_auth_rules(5) */
	status = __gss_userok(&minor, gss_info.client,
			    user_pw->pw_name, &user_ok);
	if (status == GSS_S_COMPLETE) {
		if (user_ok) {
			retval = 1;  /* remote user is a-ok */
		}
	}

#else /* SOLARIS_GSS_USEROK */

	gss_name_t imported_name;
	gss_name_t canon_name;
	gss_buffer_desc gss_user;
	OM_uint32 tmpMinor;
	int match = 0;

	if (debug)
		log_gss_info(LOG_DEBUG,
			    user_pw->pw_name, gss_info.display_name,
			    gss_info.mechoid, "gss_user: start");

	gss_user.value = user_pw->pw_name;
	gss_user.length = strlen(gss_user.value);

	status = gss_import_name(&minor,
				&gss_user,
				GSS_C_NT_USER_NAME,
				&imported_name);
	if (status != GSS_S_COMPLETE) {
		goto out;
	}

	status = gss_canonicalize_name(&minor,
				imported_name,
				gss_info.mechoid,
				&canon_name);
	if (status != GSS_S_COMPLETE) {
		(void) gss_release_name(&tmpMinor, &imported_name);
		goto out;
	}

	status = gss_compare_name(&minor,
				canon_name,
				gss_info.client,
				&match);
	(void) gss_release_name(&tmpMinor, &canon_name);
	(void) gss_release_name(&tmpMinor, &imported_name);
	if (status == GSS_S_COMPLETE) {
		if (match) {
			retval = 1; /* remote user is a-ok */
		}
	}

out:

#endif /* SOLARIS_GSS_USEROK */

	if (status != GSS_S_COMPLETE) {
		log_gss_info(LOG_ERR, user_pw->pw_name,
			    gss_info.display_name, gss_info.mechoid,
			    "gss_user failed");
		log_gss_error("gss_user failed", status, minor);
	}

	if (debug)
		syslog(LOG_DEBUG, "gss_user: end: retval=%d", retval);

	return (retval);
}


/*
 * gss_adat
 *
 * Handle ADAT(Authentication Data) command data.
 */
int
gss_adat(char *adatstr)
{
	int kerror, length;
	int replied = 0;
	int ret_flags;
	gss_buffer_desc tok, out_tok;
	gss_cred_id_t deleg_creds = NULL;
	OM_uint32 accept_maj, accept_min;
	OM_uint32 stat_maj, stat_min;
	uchar_t *gout_buf;
	size_t outlen;

	length = strlen(adatstr);
	outlen = DECODELEN(length);

	gout_buf = (uchar_t *)malloc(outlen);
	if (gout_buf == NULL) {
		reply(501, "Couldn't decode ADAT, not enough memory");
		syslog(LOG_ERR, "Couldn't decode ADAT, not enough memory");
		return (0);
	}

	if ((kerror = radix_encode((unsigned char *)adatstr,
				(unsigned char *)gout_buf,
				outlen, &length, 1))) {
		reply(501, "Couldn't decode ADAT(%s)",
		    radix_error(kerror));
		syslog(LOG_ERR, "Couldn't decode ADAT(%s)",
		    radix_error(kerror));
		return (0);
	}
	tok.value = gout_buf;
	tok.length = length;

	gss_info.context = GSS_C_NO_CONTEXT;

	/*
	 * Call accept_sec_context w/GSS_C_NO_CREDENTIAL to request
	 * default cred and to not limit the service name to one name
	 * but rather accept what the clnt requests if service
	 * princ/keys are available.
	 */
	if (debug)
		syslog(LOG_DEBUG,
		    "gss_adat: accept_sec_context will try default cred");

	out_tok.value = NULL;
	out_tok.length = 0;

	accept_maj = gss_accept_sec_context(&accept_min,
					    &gss_info.context,
					    GSS_C_NO_CREDENTIAL,
					    &tok, /* ADAT data */
					    GSS_C_NO_CHANNEL_BINDINGS,
					    &gss_info.client,
					    &gss_info.mechoid,
					    &out_tok, /* output_token */
					    (unsigned int *)&ret_flags,
					    NULL, /* ignore time_rec */
					    NULL); /* delegated creds */


	if (debug) {
		if (accept_maj == GSS_S_COMPLETE)
			syslog(LOG_DEBUG,
			    "gss_adat: accept_maj = GSS_S_COMPLETE");
		else if (accept_maj == GSS_S_CONTINUE_NEEDED)
			syslog(LOG_DEBUG,
			    "gss_adat: accept_maj = GSS_S_CONTINUE_NEEDED");
	}
	free(gout_buf);

	if (accept_maj != GSS_S_COMPLETE &&
	    accept_maj != GSS_S_CONTINUE_NEEDED) {
		reply_gss_error(535, accept_maj, accept_min,
				GSS_C_NO_OID, "accepting context");
		syslog(LOG_ERR, "failed accepting context");
		if ((ret_flags & GSS_C_DELEG_FLAG) &&
		    deleg_creds != NULL)
			(void) gss_release_cred(&stat_min,
						&deleg_creds);

		(void) gss_release_buffer(&stat_min, &out_tok);
		return (0);
	}

	if (debug)
		syslog(LOG_DEBUG, "gss_adat: out_tok.length=%d",
			out_tok.length);
	if (out_tok.length) {
		size_t buflen = ENCODELEN(out_tok.length);
		uchar_t *gbuf = (uchar_t *)malloc(buflen);
		if (gbuf == NULL) {
			reply(535, "Couldn't encode ADAT reply, "
			    "not enough memory.");
			syslog(LOG_ERR, "Couldn't encode ADAT reply, "
			    "not enough memory.");
			(void) gss_release_buffer(&stat_min, &out_tok);
			return (0);
		}
		if ((kerror = radix_encode(out_tok.value,
					(unsigned char *)gbuf,
					buflen, (int *)&out_tok.length,
					0))) {
			reply(535, "Couldn't encode ADAT reply(%s)",
			    radix_error(kerror));
			syslog(LOG_ERR, "couldn't encode ADAT reply");
			if ((ret_flags & GSS_C_DELEG_FLAG) &&
				deleg_creds != NULL)
				(void) gss_release_cred(&stat_min,
							&deleg_creds);

			(void) gss_release_buffer(&stat_min, &out_tok);
			free(gbuf);
			return (0);
		}

		if (accept_maj == GSS_S_COMPLETE) {
			reply(235, "ADAT=%s", gbuf);
			replied = 1;
		} else {
			/*
			 * If the server accepts the security data, and
			 * requires additional data, it should respond
			 * with reply code 335.
			 */
			reply(335, "ADAT=%s", gbuf);
		}
		free(gbuf);
		(void) gss_release_buffer(&stat_min, &out_tok);
	}
	if (accept_maj == GSS_S_COMPLETE) {
		gss_buffer_desc namebuf;
		gss_OID out_oid;

		/* GSSAPI authentication succeeded */
		gss_info.authstate = GSS_ADAT_DONE;
		(void) alloc_bufrec(&obr, DEF_GSSBUF_SIZE);
		(void) alloc_bufrec(&ibr, DEF_GSSBUF_SIZE);
		/*
		 * RFC 2228 - "..., once a security data exchange completes
		 * successfully, if the security mechanism supports
		 * integrity, then integrity(via the MIC or ENC command,
		 * and 631 or 632 reply) must be used, ..."
		 */
		gss_info.ctrl_prot = PROT_S;

		stat_maj = gss_display_name(&stat_min, gss_info.client,
					    &namebuf, &out_oid);
		if (stat_maj != GSS_S_COMPLETE) {
			/*
			 * RFC 2228 -
			 * "If the server rejects the security data(if
			 * a checksum fails, for instance), it should
			 * respond with reply code 535."
			 */
			reply_gss_error(535, stat_maj, stat_min,
					gss_info.mechoid,
					"extracting GSSAPI identity name");
			syslog(LOG_ERR, "gssapi error extracting identity");
			if ((ret_flags & GSS_C_DELEG_FLAG) &&
			    deleg_creds != NULL)
				(void) gss_release_cred(&stat_min,
							&deleg_creds);
			return (0);
		}
		gss_info.display_name = (char *)namebuf.value;

		if (ret_flags & GSS_C_DELEG_FLAG) {
			gss_info.have_creds = 1;
			if (deleg_creds != NULL)
				(void) gss_release_cred(&stat_min,
							&deleg_creds);
		}

		/*
		 * If the server accepts the security data, but does
		 * not require any additional data(i.e., the security
		 * data exchange has completed successfully), it must
		 * respond with reply code 235.
		 */
		if (!replied) {
			if ((ret_flags & GSS_C_DELEG_FLAG) &&
			    !gss_info.have_creds)
				reply(235,
				    "GSSAPI Authentication succeeded, but "
				    "could not accept forwarded credentials");
			else
				reply(235, "GSSAPI Authentication succeeded");
		}
		return (1);
	} else if (accept_maj == GSS_S_CONTINUE_NEEDED) {
		/*
		 * If the server accepts the security data, and
		 * requires additional data, it should respond with
		 * reply code 335.
		 */
		reply(335, "more data needed");
		if ((ret_flags & GSS_C_DELEG_FLAG) &&
		    deleg_creds != NULL)
			(void) gss_release_cred(&stat_min, &deleg_creds);
	}

	return (0);
}

/*
 * cleanup_bufrec
 *
 * cleanup the secure buffers
 */
static void
cleanup_bufrec(bufrec *brec)
{
	if (brec->buf)
		free(brec->buf);
	brec->len = 0;
	brec->clen = 0;
	brec->idx = 0;
}

static int
alloc_bufrec(bufrec *brec, size_t newsz)
{
	/*
	 * Try to allocate a buffer, if it fails,
	 * divide by 2 and try again.
	 */
	cleanup_bufrec(brec);

	while (newsz > 0 && !(brec->buf = malloc(newsz))) {
		syslog(LOG_ERR,
		    "malloc bufrec(%d bytes) failed, trying %d",
		    newsz >>= 1);
	}

	if (brec->buf == NULL)
		return (-1);

	brec->alloc_len = newsz;
	brec->len = newsz;
	brec->clen = 0;
	brec->idx = 0;
	return (0);
}

/*
 * Handle PBSZ command data, return value to caller.
 * RFC 2228 says this is a 32 bit int, so limit max value here.
 */
unsigned int
gss_setpbsz(char *pbszstr)
{
	unsigned int newsz = 0;
	char *endp;
#define	MAX_PBSZ 4294967295U

	errno = 0;
	newsz = (unsigned int)strtol(pbszstr, &endp, 10);
	if (errno != 0 || newsz > MAX_PBSZ || *endp != '\0') {
		reply(501, "Bad value for PBSZ: %s", pbszstr);
		return (0);
	}

	if (newsz > ibr.len) {
		if (alloc_bufrec(&obr, newsz) == -1) {
			perror_reply(421, "Local resource failure: malloc");
			dologout(1);
		}
		if (alloc_bufrec(&ibr, newsz) == -1) {
			perror_reply(421, "Local resource failure: malloc");
			dologout(1);
		}
	}
	reply(200, "PBSZ =%lu", ibr.len);

	return (ibr.len);
}

/*
 * sec_putbuf
 *
 * Wrap the plaintext 'buf' data using gss_wrap and send
 * it out.
 *
 * returns:
 *    bytes written (success)
 *   -1 on error(errno set)
 *   -2 on security error
 */
static int
sec_putbuf(int fd, unsigned char *buf, int len)
{
	unsigned long net_len;
	int ret = 0;
	gss_buffer_desc in_buf, out_buf;
	OM_uint32 maj_stat, min_stat;
	int conf_state;

	in_buf.value = buf;
	in_buf.length = len;
	maj_stat = gss_wrap(&min_stat, gss_info.context,
			    (gss_info.data_prot == PROT_P),
			    GSS_C_QOP_DEFAULT,
			    &in_buf, &conf_state,
			    &out_buf);

	if (maj_stat != GSS_S_COMPLETE) {
		reply_gss_error(535, maj_stat, min_stat,
				gss_info.mechoid,
				gss_info.data_prot == PROT_P ?
				"GSSAPI wrap failed":
				"GSSAPI sign failed");
		return (-2);
	}

	net_len = (unsigned long)htonl((unsigned long) out_buf.length);

	if ((ret = looping_write(fd, (const char *)&net_len, 4)) != 4) {
		syslog(LOG_ERR, "Error writing net_len(%d): %m", net_len);
		ret = -1;
		goto putbuf_done;
	}

	if ((ret = looping_write(fd, out_buf.value, out_buf.length)) !=
		out_buf.length) {
		syslog(LOG_ERR, "Error writing %d bytes: %m", out_buf.length);
		ret = -1;
		goto putbuf_done;
	}
putbuf_done:

	gss_release_buffer(&min_stat, &out_buf);
	return (ret);
}

/*
 * sec_write
 *
 * If GSSAPI security is established, encode the output
 * and write it to the client.  Else, just write it directly.
 */
int
sec_write(int fd, char *buf, int len)
{
	int nbytes = 0;
	if (gss_info.data_prot == PROT_C ||
	    !IS_GSSAUTH(cur_auth_type) ||
	    !(gss_info.authstate & GSS_ADAT_DONE))
		nbytes = write(fd, buf, len);
	else {
		/*
		 * Fill up the buffer before actually encrypting
		 * and writing it out.
		 */
		while ((obr.idx < obr.len) && (len > 0)) {
			int n, ret;

			/* how many bytes can we fit into the buffer? */
			n = (len < (obr.len - obr.idx) ? len :
			    obr.len - obr.idx);
			memcpy(obr.buf + obr.idx, buf, n);

			obr.idx += n;

			if (obr.idx >= obr.len) {
				ret = sec_putbuf(fd, (unsigned char *)obr.buf,
					obr.idx);
				obr.idx = 0;
				if (ret < 0)
					return (ret);
			}
			len -= n;
			nbytes += n;
		}
	}

	return (nbytes);
}

/*
 * CCC
 *
 * Clear Command Channel.
 *
 * We will understand this command but not allow it in a secure
 * connection.  It is very dangerous to allow someone to degrade
 * the security of the command channel.  See RFC2228 for more info.
 */
void
ccc(void)
{
	/*
	 * Once we have negotiated security successfully,
	 * do not allow the control channel to be downgraded.
	 * It should be at least SAFE if not PRIVATE.
	 */
	if (IS_GSSAUTH(cur_auth_type) &&
	    (gss_info.authstate & GSS_ADAT_DONE) == GSS_ADAT_DONE)
		reply(534, "Control channel may not be downgraded");
	else {
		gss_info.ctrl_prot = PROT_C;
		reply(200, "CCC ok");
	}
}

int
sec_putc(int c, FILE *stream)
{
	int ret = 0;
	/*
	 * If we are NOT protecting the data
	 * OR not using the GSSAPI authentication
	 * OR GSSAPI data is not yet completed, send
	 * plaintext.
	 */
	if (gss_info.data_prot == PROT_C ||
	    !IS_GSSAUTH(cur_auth_type) ||
	    !(gss_info.authstate & GSS_ADAT_DONE))
		return (putc(c, stream));

	/*
	 * Add the latest byte to the current buffer
	 */
	if (obr.idx < obr.len) {
		obr.buf[obr.idx++] = (unsigned char)(c & 0xff);
	}

	if (obr.idx == obr.len) {
		ret = sec_putbuf(fileno(stream), (uchar_t *)obr.buf, obr.idx);
		if (ret >= 0)
			ret = 0;
		obr.idx = 0;
	}

	return ((ret == 0 ? c : ret));
}

int
sec_fprintf(FILE *stream, char *fmt, ...)
{
	int ret;
	va_list ap;
	va_start(ap, fmt);

	if (gss_info.data_prot == PROT_C ||
	    !IS_GSSAUTH(cur_auth_type) ||
	    !(gss_info.authstate & GSS_ADAT_DONE)) {
		ret = vfprintf(stream, fmt, ap);
	} else {
		(void) vsnprintf(obr.buf, obr.len, fmt, ap);
		ret = sec_putbuf(fileno(stream), (unsigned char *)obr.buf,
				strlen(obr.buf));
	}
	va_end(ap);
	return (ret);
}

/*
 * sec_fflush
 *
 * If GSSAPI protection is configured, write out whatever remains
 * in the output buffer using the secure routines, otherwise
 * just flush the stream.
 */
int
sec_fflush(FILE *stream)
{
	int ret = 0;
	if (gss_info.data_prot == PROT_C ||
	    !IS_GSSAUTH(cur_auth_type) ||
	    !(gss_info.authstate & GSS_ADAT_DONE)) {
		fflush(stream);
		return (0);
	}
	if (obr.idx > 0) {
		ret = sec_putbuf(fileno(stream),
				(unsigned char *)obr.buf, obr.idx);
		obr.idx = 0;
	}

	if (ret >= 0)
		ret = sec_putbuf(fileno(stream), (unsigned char *)"", 0);
	/*
	 * putbuf returns number of bytes or a negative value,
	 * but fflush must return 0 or -1, so adjust the return
	 * value so that a positive value is interpreted as success.
	 */
	return (ret >= 0 ? 0 : ret);
}

/*
 * sec_getbytes
 *
 * Read and decrypt from the secure data channel.
 *
 * Return:
 *   > 0 == number of bytes available in gssbuf
 *   EOF == End of file.
 *   -2 == GSS error.
 *
 */
static int
sec_getbytes(int fd, char *buf, int nbytes)
{
	/*
	 * Only read from the network if our current buffer
	 * is all used up.
	 */
	if (ibr.idx >= ibr.clen) {
		int kerror;
		int conf_state;
		unsigned int length;
		gss_buffer_desc xmit_buf, msg_buf;
		OM_uint32 maj_stat, min_stat;

		if ((kerror = looping_read(fd, (char *)&length, 4)) != 4) {
			reply(535, "Couldn't read PROT buffer length: %d/%s",
			    kerror,
			    (kerror == -1) ? strerror(errno) : "premature EOF");
			return (-2);
		}

		if ((length = (unsigned int)ntohl(length)) > ibr.len) {
			reply(535, "Length(%d) > PBSZ(%d)", length, ibr.len);
			return (-2);
		}

		if (length > 0) {
			if ((kerror = looping_read(fd, ibr.buf, length)) !=
				length) {
				reply(535, "Couldn't read %u byte PROT buf: %s",
					length, (kerror == -1) ?
					strerror(errno) : "premature EOF");
				return (-2);
			}

			xmit_buf.value = (char *)ibr.buf;
			xmit_buf.length = length;

			conf_state = (gss_info.data_prot == PROT_P);

			/* decrypt/verify the message */
			maj_stat = gss_unwrap(&min_stat, gss_info.context,
					&xmit_buf, &msg_buf, &conf_state, NULL);
			if (maj_stat != GSS_S_COMPLETE) {
				reply_gss_error(535, maj_stat, min_stat,
					gss_info.mechoid,
					(gss_info.data_prot == PROT_P)?
					"failed unwrapping ENC message":
					"failed unwrapping MIC message");
				return (-2);
			}

			memcpy(ibr.buf, msg_buf.value, msg_buf.length);
			ibr.clen = msg_buf.length;
			ibr.idx = 0;

			gss_release_buffer(&min_stat, &msg_buf);
		} else {
			ibr.idx = 0;
			ibr.clen = 0;
			return (EOF);
		}
	}

	/*
	 * If there are 'nbytes' of plain text available, use them, else
	 * get whats available.
	 */
	nbytes = (nbytes < (ibr.clen - ibr.idx) ? nbytes : ibr.clen - ibr.idx);

	memcpy(buf, ibr.buf + ibr.idx, nbytes);
	ibr.idx += nbytes;

	return ((nbytes == 0 ? EOF : nbytes));
}

/*
 * Get a buffer of 'maxlen' bytes from the client.
 * If we are using GSSAPI protection, use the secure
 * input buffer.
 */
int
sec_read(int fd, char *buf, int maxlen)
{
	int nbytes = 0;

	if (gss_info.data_prot != PROT_C &&
	    IS_GSSAUTH(cur_auth_type) &&
	    (gss_info.authstate & GSS_ADAT_DONE)) {
		/* Get as much data as possible */
		nbytes = sec_getbytes(fd, buf, maxlen);
		if (nbytes == EOF)
			nbytes = 0;
	} else {
		nbytes = read(fd, buf, maxlen);
	}
	return (nbytes);
}

/*
 * sec_getc
 *
 * Get a single character from the secure network buffer.
 */
int
sec_getc(FILE *stream)
{
	int nbytes;
	unsigned char c;

	if (gss_info.data_prot != PROT_C &&
	    IS_GSSAUTH(cur_auth_type) &&
	    (gss_info.authstate & GSS_ADAT_DONE)) {
		nbytes = sec_getbytes(fileno(stream), (char *)&c, 1);
		if (nbytes > 0)
			nbytes = (int)c;
		return (nbytes);
	} else
		return (getc(stream));
}

/*
 * sec_reply
 *
 * Securely encode a reply destined for the ftp client
 * depending on the GSSAPI settings.
 */
int
sec_reply(char *buf, int bufsiz, int n)
{
	char  *out = NULL, *in = NULL;
	size_t inlen;
	gss_buffer_desc in_buf, out_buf;
	OM_uint32 maj_stat, min_stat;
	int conf_state, length, kerror;
	int ret = 0;

	if (debug)
		syslog(LOG_DEBUG, "encoding %s", buf);

	in_buf.value = buf;
	in_buf.length = strlen(buf) + 1;
	maj_stat = gss_wrap(&min_stat, gss_info.context,
			    gss_info.ctrl_prot == PROT_P,
			    GSS_C_QOP_DEFAULT,
			    &in_buf, &conf_state,
			    &out_buf);
	if (maj_stat != GSS_S_COMPLETE) {
		syslog(LOG_ERR, "gss_wrap %s did not complete",
		    (gss_info.ctrl_prot == PROT_P) ? "ENC": "MIC");
		ret = -2;
		gss_release_buffer(&min_stat, &out_buf);
		goto end;
	} else if ((gss_info.ctrl_prot == PROT_P) && !conf_state) {
		syslog(LOG_ERR, "gss_wrap did not encrypt message");
		ret = -2;
		gss_release_buffer(&min_stat, &out_buf);
		goto end;
	} else {
		out = (char *)malloc(out_buf.length);
		if (out == NULL) {
			syslog(LOG_ERR, "Memory error allocating buffer");
			ret = -2;
			gss_release_buffer(&min_stat, &out_buf);
			goto end;
		}
		memcpy(out, out_buf.value, out_buf.length);
		length = out_buf.length;
		gss_release_buffer(&min_stat, &out_buf);
		ret = 0;
	}
	/*
	 * Base64 encode the reply.  encrypted "out" becomes
	 * encoded "in" buffer.
	 * Stick it all back in 'buf' for final output.
	 */
	inlen = ENCODELEN(length);
	in = (char *)malloc(inlen);
	if (in == NULL) {
		syslog(LOG_ERR, "Memory error allocating buffer");
		ret = -2;
		goto end;
	}
	if ((kerror = radix_encode((unsigned char *)out,
				(unsigned char *)in, inlen,
				&length, 0))) {
		syslog(LOG_ERR, "Couldn't encode reply(%s)",
		    radix_error(kerror));
		strncpy(buf, in, bufsiz-1);
		buf[bufsiz - 1] = '\0';
	} else {
		snprintf(buf, bufsiz, "%s%c%s",
			gss_info.ctrl_prot == PROT_P ? "632" : "631",
			n ? ' ' : '-', in);
	}
end:
	if (in) free(in);
	if (out) free(out);

	return (ret);
}

/*
 * sec_decode_command
 *
 * If a command is received which is encoded(ENC, MIC, or CONF),
 * decode it here using GSSAPI.
 */
char *
sec_decode_command(char *cmd)
{
	char *out = NULL, *cp;
	int len, mic, outlen;
	gss_buffer_desc xmit_buf, msg_buf;
	OM_uint32 maj_stat, min_stat;
	int conf_state;
	int kerror;
	char *cs;
	char *s = cmd;

	if ((cs = strpbrk(s, " \r\n")))
		*cs++ = '\0';
	upper(s);

	if ((mic = strcmp(s, "ENC")) != 0 && strcmp(s, "MIC") &&
		strcmp(s, "CONF")) {
		reply(533, "All commands must be protected.");
		syslog(LOG_ERR, "Unprotected command received %s", s);
		*s = '\0';
		return (s);
	}

	if ((cp = strpbrk(cs, " \r\n")))
		*cp = '\0';

	outlen = DECODELEN(strlen(cs));

	out = (char *)malloc(outlen);
	if (out == NULL) {
		reply(501, "Cannot decode response - not enough memory");
		syslog(LOG_ERR, "Cannot decode response - not enough memory");
		*s = '\0';
		return (s);
	}
	len = strlen(cs);
	if ((kerror = radix_encode((unsigned char *)cs,
					(unsigned char *)out,
					outlen, &len, 1))) {
		reply(501, "Can't base 64 decode argument to %s command(%s)",
			mic ? "MIC" : "ENC", radix_error(kerror));
		*s = '\0';
		free(out);
		return (s);
	}

	if (debug)
		syslog(LOG_DEBUG, "getline got %d from %s <%s >\n",
			len, cs, mic ? "MIC" : "ENC");

	xmit_buf.value = out;
	xmit_buf.length = len;

	/* decrypt the message */
	conf_state = !mic;
	maj_stat = gss_unwrap(&min_stat, gss_info.context, &xmit_buf,
			    &msg_buf, &conf_state, NULL);
	if (maj_stat == GSS_S_CONTINUE_NEEDED) {
		if (debug) syslog(LOG_DEBUG, "%s-unwrap continued",
				mic ? "MIC" : "ENC");
		reply(535, "%s-unwrap continued, oops", mic ? "MIC" : "ENC");
		*s = 0;
		free(out);
		return (s);
	}

	free(out);
	if (maj_stat != GSS_S_COMPLETE) {
		reply_gss_error(535, maj_stat, min_stat,
				gss_info.mechoid,
				mic ? "failed unwrapping MIC message":
				"failed unwrapping ENC message");
		*s = 0;
		return (s);
	}

	memcpy(s, msg_buf.value, msg_buf.length);
	strcpy(s + msg_buf.length-(s[msg_buf.length-1] ? 0 : 1), "\r\n");
	gss_release_buffer(&min_stat, &msg_buf);

	return (s);
}

#endif /* defined(USE_GSS) */
