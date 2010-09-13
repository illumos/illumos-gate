/*
 *
 * Portions Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 *
 * This is a dummy header file for SSL
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _SSL_H
#define _SSL_H

#include <sys/types.h>

typedef void * SSL;

SSL SSL_new();
int SSL_connect(SSL s, int filedes);
int SSL_accept(SSL s, int filedes);
int SSL_read(SSL s, u_char *buf, u_int len);
int SSL_write(SSL s, u_char *buf, u_int len);
int SSL_fread(SSL s, u_char *buf, u_int len);
int SSL_fwrite(SSL s, u_char *buf, u_int len);
int SSL_flush(SSL s);
int SSL_close(SSL s);
int SSL_delete(SSL s);
char **SSL_get_supported_ciphers();
int SSL_get_cipher(SSL s, char **cipher);
int SSL_set_cipher(SSL s, char **cipher);
int SSL_set_verification(SSL s, char **root_ca_list, int *certificate_type_list);
int SSL_set_userid(SSL s, char *name, char *id);
int SSL_save_session(SSL s, u_char **id, int *len);
int SSL_set_session(SSL s, u_char *id, int len);
int SSL_delete_session(u_char *id, int len);
int SSL_errno(SSL s);
char *SSL_strerr(int err);
int SSL_get_fd(SSL s);

#endif _SSL_H
