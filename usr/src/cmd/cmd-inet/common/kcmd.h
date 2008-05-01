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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_KCMD_H
#define	_KCMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	OPTS_FORWARD_CREDS		0x00000002
#define	OPTS_FORWARDABLE_CREDS		0x00000001

#define	SERVER	0
#define	CLIENT	1

enum kcmd_proto {
	/*
	 * Old protocol: DES encryption only.  No subkeys.
	 * No protection for cleartext length.  No ivec supplied.
	 * OOB hacks used for rlogin.  Checksum may be omitted at
	 * connection startup.
	 */
	KCMD_OLD_PROTOCOL = 1,
	/*
	 * New protocol: Any encryption scheme.  Client-generated
	 * subkey required.  Prepend cleartext-length to cleartext
	 * data (but don't include it in count).  Starting ivec defined,
	 * chained.  In-band signalling.  Checksum required.
	 */
	KCMD_NEW_PROTOCOL,

	/*
	 * Hack: Get credentials, and use the old protocol iff the session
	 * key type is single-DES.
	 */
	KCMD_PROTOCOL_COMPAT_HACK,
	/* Using Kerberos version 4.  */
	KCMD_V4_PROTOCOL,
	KCMD_UNKNOWN_PROTOCOL
};

#define	SOCK_FAMILY(ss) ((ss).ss_family)

#define	SOCK_PORT(ss) ((ss).ss_family == AF_INET6 ? \
((struct sockaddr_in6 *)&(ss))->sin6_port : \
((struct sockaddr_in *)&(ss))->sin_port)

#define	SOCK_ADDR(ss) ((ss).ss_family == AF_INET6 ? \
(void *)&((struct sockaddr_in6 *)&(ss))->sin6_addr : \
(void *)&((struct sockaddr_in *)&(ss))->sin_addr)

#define	SET_SOCK_FAMILY(ss, family) (SOCK_FAMILY(ss) = (family))

#define	SET_SOCK_PORT(ss, port) \
	((ss).ss_family == AF_INET6 ? \
	(((struct sockaddr_in6 *)&(ss))->sin6_port = (port)) : \
	(((struct sockaddr_in *)&(ss))->sin_port = (port)))

#define	SET_SOCK_ADDR4(ss, addr) ((void)(sock_set_inaddr(&(ss), (addr))))

#define	SET_SOCK_ADDR_ANY(ss) \
	((void) ((ss).ss_family == AF_INET6 ? \
	(void) (((struct sockaddr_in6 *)&(ss))->sin6_addr = in6addr_any) : \
	(void) (((struct sockaddr_in *)&(ss))->sin_addr.s_addr = \
	htonl(INADDR_ANY))))

/*
 * Prototypes for functions in 'kcmd.c'
 */
char *strsave(char *sp);

int kcmd(int *sock, char **ahost, ushort_t rport, char *locuser,
	char *remuser, char *cmd, int *fd2p, char *service, char *realm,
	krb5_context bsd_context, krb5_auth_context *authconp,
	krb5_creds **cred, krb5_int32 *seqno, krb5_int32 *server_seqno,
	krb5_flags authopts,
	int anyport, enum kcmd_proto *kcmd_proto);

void init_encrypt(int, krb5_context, enum kcmd_proto,
			krb5_data *, krb5_data *,
			int, krb5_encrypt_block *);

int desread(int, char *, int, int);
int deswrite(int, char *, int, int);

#ifdef	__cplusplus
}
#endif

#endif /* _KCMD_H */
