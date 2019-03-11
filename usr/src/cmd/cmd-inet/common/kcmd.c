/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

/* derived from @(#)rcmd.c	5.17 (Berkeley) 6/27/88 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <fcntl.h>

#include <signal.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <locale.h>
#include <syslog.h>

#include <errno.h>
#include <com_err.h>
#include <k5-int.h>
#include <kcmd.h>

static char *default_service = "host";

#define	KCMD_BUFSIZ	102400
#define	KCMD8_BUFSIZ	(4096 - 256)
/*
 * For compatibility with earlier versions of Solaris and other OS
 * (kerborized rsh uses 4KB of RSH_BUFSIZE)- 256 to make sure
 * there is room
 */
static int deswrite_compat(int, char *, int, int);

#define	KCMD_KEYUSAGE	1026

static char storage[KCMD_BUFSIZ];
static int nstored = 0;
static int MAXSIZE = (KCMD_BUFSIZ + 8);
static char *store_ptr = storage;
static krb5_data desinbuf, desoutbuf;

static boolean_t encrypt_flag = B_FALSE;
static krb5_context kcmd_context;

/* XXX Overloaded: use_ivecs!=0 -> new protocol, inband signalling, etc.  */
static boolean_t use_ivecs = B_FALSE;
static krb5_data encivec_i[2], encivec_o[2];
static krb5_keyusage enc_keyusage_i[2], enc_keyusage_o[2];
static krb5_enctype final_enctype;
static krb5_keyblock *skey;

/* ARGSUSED */
int
kcmd(int *sock, char **ahost, ushort_t rport,
	char *locuser, char *remuser,
	char *cmd, int *fd2p, char *service, char *realm,
	krb5_context bsd_context, krb5_auth_context *authconp,
	krb5_creds **cred, krb5_int32 *seqno, krb5_int32 *server_seqno,
	krb5_flags authopts,
	int anyport, enum kcmd_proto *protonump)
{
	int s = -1;
	sigset_t oldmask, urgmask;
	struct sockaddr_in sin;
	struct sockaddr_storage from;
	krb5_creds *get_cred = NULL;
	krb5_creds *ret_cred = NULL;
	char c;
	struct hostent *hp;
	int rc;
	char *host_save = NULL;
	krb5_error_code status;
	krb5_ap_rep_enc_part *rep_ret;
	krb5_error	*error = 0;
	krb5_ccache cc;
	krb5_data outbuf;
	krb5_flags options = authopts;
	krb5_auth_context auth_context = NULL;
	char *cksumbuf;
	krb5_data cksumdat;
	int bsize = 0;
	char *kcmd_version;
	enum kcmd_proto protonum = *protonump;

	bsize = strlen(cmd) + strlen(remuser) + 64;
	if ((cksumbuf = malloc(bsize)) == 0) {
		(void) fprintf(stderr, gettext("Unable to allocate"
					    " memory for checksum buffer.\n"));
		return (-1);
	}
	(void) snprintf(cksumbuf, bsize, "%u:", ntohs(rport));
	if (strlcat(cksumbuf, cmd, bsize) >= bsize) {
		(void) fprintf(stderr, gettext("cmd buffer too long.\n"));
		free(cksumbuf);
		return (-1);
	}
	if (strlcat(cksumbuf, remuser, bsize) >= bsize) {
		(void) fprintf(stderr, gettext("remuser too long.\n"));
		free(cksumbuf);
		return (-1);
	}
	cksumdat.data = cksumbuf;
	cksumdat.length = strlen(cksumbuf);

	hp = gethostbyname(*ahost);
	if (hp == 0) {
		(void) fprintf(stderr,
			    gettext("%s: unknown host\n"), *ahost);
		return (-1);
	}

	if ((host_save = (char *)strdup(hp->h_name)) == NULL) {
		(void) fprintf(stderr, gettext("kcmd: no memory\n"));
		return (-1);
	}

	/* If no service is given set to the default service */
	if (!service) service = default_service;

	if (!(get_cred = (krb5_creds *)calloc(1, sizeof (krb5_creds)))) {
		(void) fprintf(stderr, gettext("kcmd: no memory\n"));
		return (-1);
	}
	(void) sigemptyset(&urgmask);
	(void) sigaddset(&urgmask, SIGURG);
	(void) sigprocmask(SIG_BLOCK, &urgmask, &oldmask);

	status = krb5_sname_to_principal(bsd_context, host_save, service,
					KRB5_NT_SRV_HST, &get_cred->server);
	if (status) {
		(void) fprintf(stderr,
			    gettext("kcmd: "
				    "krb5_sname_to_principal failed: %s\n"),
			    error_message(status));
		status = -1;
		goto bad;
	}

	if (realm && *realm) {
		(void) krb5_xfree(
			krb5_princ_realm(bsd_context, get_cred->server)->data);
		krb5_princ_set_realm_length(bsd_context, get_cred->server,
					strlen(realm));
		krb5_princ_set_realm_data(bsd_context, get_cred->server,
						strdup(realm));
	}

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror(gettext("Error creating socket"));
		status = -1;
		goto bad;
	}
	/*
	 * Kerberos only supports IPv4 addresses for now.
	 */
	if (hp->h_addrtype == AF_INET) {
		sin.sin_family = hp->h_addrtype;
		(void) memcpy((void *)&sin.sin_addr,
			    hp->h_addr, hp->h_length);
		sin.sin_port = rport;
	} else {
		syslog(LOG_ERR, "Address type %d not supported for "
		    "Kerberos", hp->h_addrtype);
		status = -1;
		goto bad;
	}

	if (connect(s, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
		perror(host_save);
		status = -1;
		goto bad;
	}

	if (fd2p == 0) {
		(void) write(s, "", 1);
	} else {
		char num[16];
		int s2;
		int s3;
		struct sockaddr_storage sname;
		struct sockaddr_in *sp;
		int len = sizeof (struct sockaddr_storage);

		s2 = socket(AF_INET, SOCK_STREAM, 0);
		if (s2 < 0) {
			status = -1;
			goto bad;
		}
		(void) memset((char *)&sin, 0, sizeof (sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = INADDR_ANY;
		sin.sin_port = 0;

		if (bind(s2, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
			perror(gettext("error binding socket"));
			(void) close(s2);
			status = -1;
			goto bad;
		}
		if (getsockname(s2, (struct sockaddr *)&sname, &len) < 0) {
			perror(gettext("getsockname error"));
			(void) close(s2);
			status = -1;
			goto bad;
		}
		sp = (struct sockaddr_in *)&sname;
		(void) listen(s2, 1);
		(void) snprintf(num, sizeof (num), "%d",
			    htons((ushort_t)sp->sin_port));
		if (write(s, num, strlen(num)+1) != strlen(num)+1) {
			perror(gettext("write: error setting up stderr"));
			(void) close(s2);
			status = -1;
			goto bad;
		}

		s3 = accept(s2, (struct sockaddr *)&from, &len);
		(void) close(s2);
		if (s3 < 0) {
			perror(gettext("accept"));
			status = -1;
			goto bad;
		}
		*fd2p = s3;
		if (SOCK_FAMILY(from) == AF_INET) {
			if (!anyport && SOCK_PORT(from) >= IPPORT_RESERVED) {
				(void) fprintf(stderr,
				    gettext("socket: protocol "
					    "failure in circuit setup.\n"));
				status = -1;
				goto bad2;
			}
		} else {
			(void) fprintf(stderr,
				    gettext("Kerberos does not support "
					    "address type %d\n"),
				    SOCK_FAMILY(from));
			status = -1;
			goto bad2;
		}
	}

	if (status = krb5_cc_default(bsd_context, &cc))
		goto bad2;

	status = krb5_cc_get_principal(bsd_context, cc, &get_cred->client);
	if (status) {
		(void) krb5_cc_close(bsd_context, cc);
		goto bad2;
	}

	/* Get ticket from credentials cache or kdc */
	status = krb5_get_credentials(bsd_context, 0, cc, get_cred, &ret_cred);
	(void) krb5_cc_close(bsd_context, cc);
	if (status) goto bad2;

	/* Reset internal flags; these should not be sent. */
	authopts &= (~OPTS_FORWARD_CREDS);
	authopts &= (~OPTS_FORWARDABLE_CREDS);

	if ((status = krb5_auth_con_init(bsd_context, &auth_context)))
		goto bad2;

	if ((status = krb5_auth_con_setflags(bsd_context, auth_context,
					KRB5_AUTH_CONTEXT_RET_TIME)))
		goto bad2;

	/* Only need local address for mk_cred() to send to krlogind */
	if ((status = krb5_auth_con_genaddrs(bsd_context, auth_context, s,
			KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR)))
		goto bad2;

	if (protonum == KCMD_PROTOCOL_COMPAT_HACK) {
		krb5_boolean is_des;
		status = krb5_c_enctype_compare(bsd_context,
						ENCTYPE_DES_CBC_CRC,
						ret_cred->keyblock.enctype,
						&is_des);
		if (status)
			goto bad2;
		protonum = is_des ? KCMD_OLD_PROTOCOL : KCMD_NEW_PROTOCOL;
	}

	switch (protonum) {
	case KCMD_NEW_PROTOCOL:
		authopts |= AP_OPTS_USE_SUBKEY;
		kcmd_version = "KCMDV0.2";
		break;
	case KCMD_OLD_PROTOCOL:
		kcmd_version = "KCMDV0.1";
		break;
	default:
		status = -1;
		goto bad2;
	}

	/*
	 * Call the Kerberos library routine to obtain an authenticator,
	 * pass it over the socket to the server, and obtain mutual
	 * authentication.
	 */
	status = krb5_sendauth(bsd_context, &auth_context, (krb5_pointer) &s,
			kcmd_version, ret_cred->client, ret_cred->server,
			authopts, &cksumdat, ret_cred, 0, &error,
			&rep_ret, NULL);
	krb5_xfree(cksumdat.data);
	if (status) {
		(void) fprintf(stderr, gettext("Couldn't authenticate"
					    " to server: %s\n"),
			    error_message(status));
		if (error) {
			(void) fprintf(stderr, gettext("Server returned error"
						" code %d (%s)\n"),
				error->error,
				error_message(ERROR_TABLE_BASE_krb5 +
					    error->error));
			if (error->text.length)
				(void) fprintf(stderr,
					    gettext("Error text"
						    " sent from server: %s\n"),
					    error->text.data);
		}
		if (error) {
			krb5_free_error(bsd_context, error);
			error = 0;
		}
		goto bad2;
	}
	if (rep_ret && server_seqno) {
		*server_seqno = rep_ret->seq_number;
		krb5_free_ap_rep_enc_part(bsd_context, rep_ret);
	}

	(void) write(s, remuser, strlen(remuser)+1);
	(void) write(s, cmd, strlen(cmd)+1);
	if (locuser)
		(void) write(s, locuser, strlen(locuser)+1);
	else
		(void) write(s, "", 1);

	if (options & OPTS_FORWARD_CREDS) {   /* Forward credentials */
		if (status = krb5_fwd_tgt_creds(bsd_context, auth_context,
					host_save,
					ret_cred->client, ret_cred->server,
					0, options & OPTS_FORWARDABLE_CREDS,
					&outbuf)) {
			(void) fprintf(stderr,
				    gettext("kcmd: Error getting"
					    " forwarded creds\n"));
			goto bad2;
		}
		/* Send forwarded credentials */
		if (status = krb5_write_message(bsd_context, (krb5_pointer)&s,
						&outbuf))
			goto bad2;
	} else { /* Dummy write to signal no forwarding */
		outbuf.length = 0;
		if (status = krb5_write_message(bsd_context,
						(krb5_pointer)&s, &outbuf))
			goto bad2;
	}

	if ((rc = read(s, &c, 1)) != 1) {
		if (rc == -1) {
			perror(*ahost);
		} else {
			(void) fprintf(stderr, gettext("kcmd: bad connection "
					"with remote host\n"));
		}
		status = -1;
		goto bad2;
	}
	if (c != 0) {
		while (read(s, &c, 1) == 1) {
			(void) write(2, &c, 1);
			if (c == '\n')
				break;
		}
		status = -1;
		goto bad2;
	}
	(void) sigprocmask(SIG_SETMASK, &oldmask, (sigset_t *)0);
	*sock = s;

	/* pass back credentials if wanted */
	if (cred)
		(void) krb5_copy_creds(bsd_context, ret_cred, cred);

	krb5_free_creds(bsd_context, ret_cred);

	/*
	 * Initialize *authconp to auth_context, so
	 * that the clients can make use of it
	 */
	*authconp = auth_context;

	return (0);
bad2:
	if (fd2p != NULL)
		(void) close(*fd2p);
bad:
	if (s > 0)
		(void) close(s);
	if (get_cred)
		krb5_free_creds(bsd_context, get_cred);
	if (ret_cred)
		krb5_free_creds(bsd_context, ret_cred);
	if (host_save)
		free(host_save);
	(void) sigprocmask(SIG_SETMASK, &oldmask, (sigset_t *)0);
	return (status);
}

/*
 * Strsave was a routine in the version 4 krb library: we put it here
 * for compatablilty with version 5 krb library, since kcmd.o is linked
 * into all programs.
 */

char *
strsave(char *sp)
{
	char *ret;

	if ((ret = (char *)strdup(sp)) == NULL) {
		(void) fprintf(stderr, gettext("no memory for saving args\n"));
		exit(1);
	}
	return (ret);
}


/*
 * This routine is to initialize the desinbuf, desoutbuf and the session key
 * structures to carry out desread()'s and deswrite()'s successfully
 */
void
init_encrypt(int enc, krb5_context ctxt, enum kcmd_proto protonum,
	krb5_data *inbuf, krb5_data *outbuf,
	int amclient, krb5_encrypt_block *block)
{
	krb5_error_code statuscode;
	size_t blocksize;
	int i;
	krb5_error_code ret;

	kcmd_context = ctxt;

	if (enc > 0) {
		desinbuf.data = inbuf->data;
		desoutbuf.data = outbuf->data + 4;
		desinbuf.length = inbuf->length;
		desoutbuf.length = outbuf->length + 4;
		encrypt_flag = B_TRUE;
	} else {
		encrypt_flag = B_FALSE;
		return;
	}

	skey = block->key;
	final_enctype = skey->enctype;

	enc_keyusage_i[0] = KCMD_KEYUSAGE;
	enc_keyusage_i[1] = KCMD_KEYUSAGE;
	enc_keyusage_o[0] = KCMD_KEYUSAGE;
	enc_keyusage_o[1] = KCMD_KEYUSAGE;

	if (protonum == KCMD_OLD_PROTOCOL) {
		use_ivecs = B_FALSE;
		return;
	}

	use_ivecs = B_TRUE;
	switch (skey->enctype) {
	/*
	 * For the DES-based enctypes and the 3DES enctype we
	 * want to use a non-zero  IV because that's what we did.
	 * In the future we use different keyusage for each
	 * channel and direction and a fresh cipher state.
	 */
	case ENCTYPE_DES_CBC_CRC:
	case ENCTYPE_DES_CBC_MD4:
	case ENCTYPE_DES_CBC_MD5:
	case ENCTYPE_DES3_CBC_SHA1:
		statuscode = krb5_c_block_size(kcmd_context, final_enctype,
				&blocksize);
		if (statuscode) {
			/* XXX what do I do? */
			abort();
		}

		encivec_i[0].length = encivec_i[1].length =
		encivec_o[0].length = encivec_o[1].length = blocksize;

		if ((encivec_i[0].data = malloc(encivec_i[0].length * 4))
			== NULL) {
			/* XXX what do I do? */
			abort();
		}
		encivec_i[1].data = encivec_i[0].data + encivec_i[0].length;
		encivec_o[0].data = encivec_i[1].data + encivec_i[0].length;
		encivec_o[1].data = encivec_o[0].data + encivec_i[0].length;

		/* is there a better way to initialize this? */
		(void) memset(encivec_i[0].data, amclient, blocksize);
		(void) memset(encivec_o[0].data, 1 - amclient, blocksize);
		(void) memset(encivec_i[1].data, 2 | amclient, blocksize);
		(void) memset(encivec_o[1].data, 2 | (1 - amclient), blocksize);
		break;
	default:
		if (amclient) {
			enc_keyusage_i[0] = 1028;
			enc_keyusage_i[1] = 1030;
			enc_keyusage_o[0] = 1032;
			enc_keyusage_o[1] = 1034;
		} else { /* amclient */
			enc_keyusage_i[0] = 1032;
			enc_keyusage_i[1] = 1034;
			enc_keyusage_o[0] = 1028;
			enc_keyusage_o[1] = 1030;
		}
		for (i = 0; i < 2; i++) {
			ret = krb5_c_init_state(ctxt,
				skey, enc_keyusage_i[i],
				&encivec_i[i]);
			if (ret)
				goto fail;
			ret = krb5_c_init_state(ctxt,
				skey, enc_keyusage_o[i],
				&encivec_o[i]);
			if (ret)
				goto fail;
		}
		break;
	}
	return;
fail:
	abort();
}

int
desread(int fd, char *buf, int len, int secondary)
{
	int nreturned = 0;
	long net_len, rd_len;
	int cc;
	size_t ret = 0;
	unsigned char len_buf[4];
	krb5_enc_data inputd;
	krb5_data outputd;

	if (!encrypt_flag)
		return (read(fd, buf, len));

	/*
	 * If there is stored data from a previous read,
	 * put it into the output buffer and return it now.
	 */
	if (nstored >= len) {
		(void) memcpy(buf, store_ptr, len);
		store_ptr += len;
		nstored -= len;
		return (len);
	} else if (nstored) {
		(void) memcpy(buf, store_ptr, nstored);
		nreturned += nstored;
		buf += nstored;
		len -= nstored;
		nstored = 0;
	}

	if ((cc = krb5_net_read(kcmd_context, fd, (char *)len_buf, 4)) != 4) {
		if ((cc < 0) && ((errno == EWOULDBLOCK) || (errno == EAGAIN)))
			return (cc);
		/* XXX can't read enough, pipe must have closed */
		return (0);
	}
	rd_len = ((len_buf[0] << 24) | (len_buf[1] << 16) |
		    (len_buf[2] << 8) | len_buf[3]);

	if (krb5_c_encrypt_length(kcmd_context, final_enctype,
				use_ivecs ? (size_t)rd_len + 4 : (size_t)rd_len,
				&ret))
		net_len = ((size_t)-1);
	else
		net_len = ret;

	if ((net_len <= 0) || (net_len > desinbuf.length)) {
		/*
		 * preposterous length; assume out-of-sync; only recourse
		 * is to close connection, so return 0
		 */
		(void) fprintf(stderr, gettext("Read size problem.\n"));
		return (0);
	}

	if ((cc = krb5_net_read(kcmd_context, fd, desinbuf.data, net_len))
	    != net_len) {
		/* pipe must have closed, return 0 */
		(void) fprintf(stderr,
			    gettext("Read error: length received %d "
				    "!= expected %d.\n"),
			    cc, net_len);
		return (0);
	}

	/*
	 * Decrypt information
	 */
	inputd.enctype = ENCTYPE_UNKNOWN;
	inputd.ciphertext.length = net_len;
	inputd.ciphertext.data = (krb5_pointer)desinbuf.data;

	outputd.length = sizeof (storage);
	outputd.data = (krb5_pointer)storage;

	/*
	 * data is decrypted into the "storage" buffer, which
	 * had better be large enough!
	 */
	cc = krb5_c_decrypt(kcmd_context, skey,
				enc_keyusage_i[secondary],
				use_ivecs ? encivec_i + secondary : 0,
				&inputd, &outputd);
	if (cc) {
		(void) fprintf(stderr, gettext("Cannot decrypt data "
			"from network\n"));
		return (0);
	}

	store_ptr = storage;
	nstored = rd_len;
	if (use_ivecs == B_TRUE) {
		int rd_len2;
		rd_len2 = storage[0] & 0xff;
		rd_len2 <<= 8; rd_len2 |= storage[1] & 0xff;
		rd_len2 <<= 8; rd_len2 |= storage[2] & 0xff;
		rd_len2 <<= 8; rd_len2 |= storage[3] & 0xff;
		if (rd_len2 != rd_len) {
			/* cleartext length trashed? */
			errno = EIO;
			return (-1);
		}
		store_ptr += 4;
	}
	/*
	 * Copy only as much data as the input buffer will allow.
	 * The rest is kept in the 'storage' pointer for the next
	 * read.
	 */
	if (nstored > len) {
		(void) memcpy(buf, store_ptr, len);
		nreturned += len;
		store_ptr += len;
		nstored -= len;
	} else {
		(void) memcpy(buf, store_ptr, nstored);
		nreturned += nstored;
		nstored = 0;
	}

	return (nreturned);
}
int
deswrite(int fd, char *buf, int len, int secondary)
{
	int bytes_written;
	int r;
	int outlen;
	char *p;
	if (!encrypt_flag)
		return (write(fd, buf, len));

	bytes_written = 0;
	while (len > 0) {
		p = buf + bytes_written;
		if (len > KCMD8_BUFSIZ)
			outlen = KCMD8_BUFSIZ;
		else
			outlen = len;
		r = deswrite_compat(fd, p, outlen, secondary);
		if (r == -1)
			return (r);
		bytes_written += r;
		len -= r;
	}
	return (bytes_written);
}
static int
deswrite_compat(int fd, char *buf, int len, int secondary)
{
	int cc;
	size_t ret = 0;
	krb5_data inputd;
	krb5_enc_data outputd;
	char tmpbuf[KCMD_BUFSIZ + 8];
	char encrbuf[KCMD_BUFSIZ + 8];
	unsigned char *len_buf = (unsigned char *)tmpbuf;

	if (use_ivecs == B_TRUE) {
		unsigned char *lenbuf2 = (unsigned char *)tmpbuf;
		if (len + 4 > sizeof (tmpbuf))
			abort();
		lenbuf2[0] = (len & 0xff000000) >> 24;
		lenbuf2[1] = (len & 0xff0000) >> 16;
		lenbuf2[2] = (len & 0xff00) >> 8;
		lenbuf2[3] = (len & 0xff);
		(void) memcpy(tmpbuf + 4, buf, len);

		inputd.data = (krb5_pointer)tmpbuf;
		inputd.length = len + 4;
	} else {
		inputd.data = (krb5_pointer)buf;
		inputd.length = len;
	}

	desoutbuf.data = encrbuf;

	if (krb5_c_encrypt_length(kcmd_context, final_enctype,
			use_ivecs ? (size_t)len + 4 : (size_t)len, &ret)) {
		desoutbuf.length = ((size_t)-1);
		goto err;
	} else {
		desoutbuf.length = ret;
	}

	if (desoutbuf.length > MAXSIZE) {
		(void) fprintf(stderr, gettext("Write size problem.\n"));
		return (-1);
	}

	/*
	 * Encrypt information
	 */
	outputd.ciphertext.length = desoutbuf.length;
	outputd.ciphertext.data = (krb5_pointer)desoutbuf.data;

	cc = krb5_c_encrypt(kcmd_context, skey,
			enc_keyusage_o[secondary],
			use_ivecs ? encivec_o + secondary : 0,
			&inputd, &outputd);

	if (cc) {
err:
		(void) fprintf(stderr, gettext("Write encrypt problem.\n"));
		return (-1);
	}

	len_buf[0] = (len & 0xff000000) >> 24;
	len_buf[1] = (len & 0xff0000) >> 16;
	len_buf[2] = (len & 0xff00) >> 8;
	len_buf[3] = (len & 0xff);
	(void) write(fd, len_buf, 4);

	if (write(fd, desoutbuf.data, desoutbuf.length) != desoutbuf.length) {
		(void) fprintf(stderr, gettext("Could not write "
			"out all data.\n"));
		return (-1);
	} else {
		return (len);
	}
}
