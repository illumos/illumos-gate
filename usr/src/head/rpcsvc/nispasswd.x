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
 * NIS+ password update protocol
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

%#include <limits.h>

/*
 * Protocol description:
 * 	Request from client:
 * Key_type = DES; CK = common DES key generated from Pub.D and Sec.C
 *	Response from daemon:
 * Key_type = DES; CK = common DES key generated from Pub.C and Sec.D
 *
 * Client							Daemon
 *
 *  ------------------------------------------------------------------->
 *  [ Username, Domain, Key_type, Publickey.C, CK(clear_password), ID ]
 *
 *
 *  <-------------------------------------------------------------------
 *		[NPD_SUCCESS, CK(ID, Random_value) ]
 *		[NPD_TRYAGAIN, CK(ID, Random_value) ]
 *		[NPD_FAILED, <code> ]
 *
 *		{ repeat above req/resp as necessary }
 *
 *  -------------------------------------------------------------------->
 *		[ ID, CK(R, clear_new_passwd), other_passwd_info ]
 *
 *
 *  <--------------------------------------------------------------------
 *		[NPD_SUCCESS]
 *		[NPD_PARTIALSUCCESS, <field>/<code> ]
 *		[NPD_FAILED, <code> ]
 *
 */

/*
 * status of operation, NPD = NIS+ PASSWD DAEMON
 */
enum nispasswd_status {
	NPD_SUCCESS,		/* operation succeeded */
	NPD_TRYAGAIN,		/* passwd incorrect, try again */
	NPD_PARTIALSUCCESS,	/* failed to update all the info */
	NPD_FAILED		/* operation failed */
};

/*
 * error codes
 */
enum nispasswd_code {
	NPD_NOTMASTER,		/* server is not master of this domain */
	NPD_NOSUCHENTRY,	/* no passwd entry exists for this user */
	NPD_IDENTINVALID,	/* identifier invalid */
	NPD_NOPASSWD,		/* no password stored */
	NPD_NOSHDWINFO,		/* no shadow information stored */
	NPD_SHDWCORRUPT,	/* shadow information corrupted */
	NPD_NOTAGED,		/* passwd has not aged sufficiently */
	NPD_CKGENFAILED,	/* common key could not be generated */
	NPD_VERFINVALID,	/* verifier mismatch */
	NPD_PASSINVALID,	/* all auth attempts incorrect */
	NPD_ENCRYPTFAIL,	/* encryption failed */
	NPD_DECRYPTFAIL,	/* decryption failed */
	NPD_KEYSUPDATED,	/* new key-pair generated for user */
	NPD_KEYNOTREENC,	/* could not reencrypt secret key */
	NPD_PERMDENIED,		/* permission denied */
	NPD_SRVNOTRESP,		/* server not responding */
	NPD_NISERROR,		/* NIS+ server error */
	NPD_SYSTEMERR,		/* system error */
	NPD_BUFTOOSMALL,	/* buffer too small */
	NPD_INVALIDARGS		/* invalid args to function */

	/* others */
};

/*
 * other passwd fields that change and secretkey
 */
enum nispasswd_field {
	NPD_PASSWD,		/* password field */
	NPD_GECOS,		/* gecos field */
	NPD_SHELL,		/* shell field */
	NPD_SECRETKEY		/* secret key */
};

/*
 * error reason
 */

struct nispasswd_error {
	nispasswd_field		npd_field;	/* field type */
	nispasswd_code		npd_code;	/* error code */
	struct nispasswd_error	*next;		/* next pair */
};

/*
 * other passwd information
 */
struct passwd_info {
	string	pw_gecos<>;	/* in real life name */
	string	pw_shell<>;	/* default shell */
};

struct npd_request {
	string		username<>;	/* update req. for username */
	string		domain<>;	/* update in domain */
	string		key_type<>;	/* DES, RSA, KERB */
	unsigned char	user_pub_key<>;	/* generated publickey */
	unsigned char	npd_authpass<>;	/* encrypted passwd */
	unsigned int	ident;		/* identifier */
};

/*
 * encrypted passwd information
 */
const __NPD_MAXPASSBYTES = 12;
typedef opaque passbuf[__NPD_MAXPASSBYTES];	/* store encrypted pass */

struct npd_newpass {
	unsigned int	npd_xrandval;	/* R */
	passbuf	pass;			/* "clear" new passwd */
};

struct npd_update {
	unsigned int	ident;			/* identifier */
	npd_newpass	xnewpass;		/* encrypted */
	passwd_info	pass_info;		/* other information */
};

%#define DESCREDPASSLEN sizeof (des_block)
const __NPD2_MAXPASSBYTES = 256;		/* _PASS_MAX */

struct npd_newpass2 {
	unsigned int	npd_xrandval;		/* R */
	opaque	pass[__NPD2_MAXPASSBYTES];	/* "clear" new passwd */
	unsigned int	npd_pad;	/* pad size to modulo des_block */
};

struct npd_update2 {
	unsigned int	ident;			/* identifier */
	npd_newpass2	xnewpass;		/* encrypted */
	passwd_info	pass_info;		/* other information */
};

struct nispasswd_verf {
	unsigned int	npd_xid;		/* encrypted identifier */
	unsigned int	npd_xrandval;		/* encrypted R */
};

/*
 * authentication result
 */
union nispasswd_authresult switch (nispasswd_status status) {
case NPD_SUCCESS:
case NPD_TRYAGAIN:
	nispasswd_verf		npd_verf;	/* verifier */
default:
	nispasswd_code		npd_err;	/* error */
};

/*
 * update result
 */
union nispasswd_updresult switch (nispasswd_status status) {
case NPD_PARTIALSUCCESS:
	nispasswd_error		reason;		/* field/code */
case NPD_FAILED:
	nispasswd_code		npd_err;	/* error */
default:
	void;
};

program NISPASSWD_PROG {
	version NISPASSWD_VERS {
		/*
		 * authenticate passwd update request
		 */
		nispasswd_authresult NISPASSWD_AUTHENTICATE(npd_request) = 1;

		/*
		 * send new passwd information
		 */
		nispasswd_updresult	NISPASSWD_UPDATE(npd_update) = 2;
	} = 1;

	version NISPASSWD_VERS2 {
		/*
		 * authenticate passwd update request
		 */
		nispasswd_authresult NISPASSWD_AUTHENTICATE(npd_request) = 1;

		/*
		 * send new passwd information
		 */
		nispasswd_updresult	NISPASSWD_UPDATE(npd_update2) = 2;
	} = 2;
} = 100303;
