/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _GSSUTIL_H
#define	_GSSUTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <gssapi/gssapi.h>
#ifdef SOLARIS_2
#include <gssapi/gssapi_ext.h>
#else
#include <gssapi/gssapi_generic.h>
#endif

#ifndef SOLARIS_2
#define	GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#endif

#ifndef g_OID_equal
#define	g_OID_equal(o1, o2) \
	(((o1)->length == (o2)->length) && \
	(memcmp((o1)->elements, (o2)->elements, (int)(o1)->length) == 0))
#endif /* g_OID_equal */

#define	GSS_AUTH_NONE 0x00
#define	GSS_ADAT_DONE 0x01
#define	GSS_USER_DONE 0x02
#define	GSS_PWD_DONE  0x04

typedef struct gss_inforec {
	gss_ctx_id_t	context;
	gss_OID		mechoid;
	gss_name_t	client;
	char		*display_name;
	unsigned char	data_prot;
	unsigned char	ctrl_prot;
	unsigned char	authstate;
	unsigned char	want_creds;
	unsigned char	have_creds;
	unsigned char	must_gss_auth;
} gss_info_t;

#define	GSSUSERAUTH_OK(x) (((x).authstate & (GSS_ADAT_DONE|GSS_USER_DONE)) \
== (GSS_ADAT_DONE|GSS_USER_DONE))

#define	IS_GSSAUTH(s) ((s) != NULL && (strcmp((s), "GSSAPI") == 0))

int gss_user(struct passwd *);
int gss_adat(char *adatstr);
unsigned int gss_setpbsz(char *pbszstr);
int sec_write(int fd, char *buf, int len);
void ccc(void);
int sec_putc(int c, FILE *stream);
int sec_getc(FILE *stream);
int sec_fprintf(FILE *stream, char *fmt, ...);
int sec_fflush(FILE *stream);
int sec_read(int fd, char *buf, int maxlen);
int sec_reply(char *buf, int bufsiz, int n);
char *sec_decode_command(char *cmd);
size_t gss_getinbufsz(void);
void gss_adjust_buflen(void);

#ifdef __cplusplus
}
#endif

#endif /* _GSSUTIL_H */
