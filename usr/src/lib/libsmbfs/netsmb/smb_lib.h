/*
 * Copyright (c) 2000-2001 Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smb_lib.h,v 1.21.82.2 2005/06/02 00:55:39 lindak Exp $
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NETSMB_SMB_LIB_H_
#define	_NETSMB_SMB_LIB_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/byteorder.h>

#include <netsmb/smb.h>
#include <netsmb/smb_dev.h>

#define	SMB_CFG_FILE	"/etc/nsmb.conf"
#define	OLD_SMB_CFG_FILE	"/usr/local/etc/nsmb.conf"

#define	STDPARAM_ARGS	\
	'A':case 'B':case 'C':case 'E':case 'I':case 'L':case \
	'M':case 'N':case 'U':case 'R':case 'S':case 'T':case \
	'W':case 'O':case 'P'

#define	STDPARAM_OPT	"ABCE:I:L:M:NO:P:U:R:S:T:W:"

/*
 * bits to indicate the source of error
 */
#define	SMB_ERRTYPE_MASK	0xf0000
#define	SMB_SYS_ERROR		0x00000
#define	SMB_RAP_ERROR		0x10000
#define	SMB_NB_ERROR		0x20000

/*
 * SMB work context. Used to store all values which are necessary
 * to establish connection to an SMB server.
 */
struct smb_ctx {
	int		ct_flags;	/* SMBCF_ */
	int		ct_fd;		/* handle of connection */
	int		ct_parsedlevel;
	int		ct_minlevel;
	int		ct_maxlevel;
	char		*ct_fullserver; /* original server name from cmd line */
	char		*ct_srvaddr;	/* hostname or IP address of server */
	struct sockaddr_in ct_srvinaddr; /* IP address of server */
	char		ct_locname[SMB_MAXUSERNAMELEN + 1];
	struct nb_ctx	*ct_nb;
	struct smbioc_ossn	ct_ssn;
	struct smbioc_oshare	ct_sh;
	char		*ct_origshare;
	char		*ct_home;
	void		*ct_secblob;
	int		ct_secbloblen;
	/* krb5 stuff: all anonymous struct pointers here. */
	struct _krb5_context *ct_krb5ctx;
	struct _krb5_ccache *ct_krb5cc; 	/* credentials cache */
	struct krb5_principal_data *ct_krb5cp;	/* client principal */
};
typedef struct smb_ctx smb_ctx_t;

#define	SMBCF_NOPWD		    0x0001 /* don't ask for a password */
#define	SMBCF_SRIGHTS		    0x0002 /* share access rights supplied */
#define	SMBCF_LOCALE		    0x0004 /* use current locale */
#define	SMBCF_CMD_DOM		    0x0010 /* CMD specified domain */
#define	SMBCF_CMD_USR		    0x0020 /* CMD specified user */
#define	SMBCF_CMD_PW		    0x0040 /* CMD specified password */
#define	SMBCF_RESOLVED		    0x8000 /* structure has been verified */
#define	SMBCF_KCBAD		0x00080000 /* keychain password failed */
#define	SMBCF_KCFOUND		0x00100000 /* password is from keychain */
#define	SMBCF_BROWSEOK		0x00200000 /* browser dialogue may be used */
#define	SMBCF_AUTHREQ		0x00400000 /* auth. dialog requested */
#define	SMBCF_KCSAVE		0x00800000 /* add to keychain requested */
#define	SMBCF_XXX		0x01000000 /* mount-all, a very bad thing */
#define	SMBCF_SSNACTIVE		0x02000000 /* session setup succeeded */
#define	SMBCF_KCDOMAIN		0x04000000 /* use domain in KC lookup */

/*
 * access modes (see also smb_dev.h)
 */
#define	SMBM_READ	S_IRUSR	/* read conn attrs. (like list shares) */
#define	SMBM_WRITE	S_IWUSR	/* modify conn attrs */
#define	SMBM_EXEC	S_IXUSR	/* can send SMB requests */
#define	SMBM_READGRP	S_IRGRP
#define	SMBM_WRITEGRP	S_IWGRP
#define	SMBM_EXECGRP	S_IXGRP
#define	SMBM_READOTH	S_IROTH
#define	SMBM_WRITEOTH	S_IWOTH
#define	SMBM_EXECOTH	S_IXOTH
#define	SMBM_ALL	S_IRWXU
#define	SMBM_DEFAULT	S_IRWXU


/*
 * Share type for smb_ctx_init
 */
#define	SMB_ST_DISK		STYPE_DISKTREE
#define	SMB_ST_PRINTER		STYPE_PRINTQ
#define	SMB_ST_COMM		STYPE_DEVICE
#define	SMB_ST_PIPE		STYPE_IPC
#define	SMB_ST_ANY		STYPE_UNKNOWN
#define	SMB_ST_MAX		STYPE_UNKNOWN
#define	SMB_ST_NONE		0xff	/* not a part of protocol */

struct mbdata {
	struct mbuf	*mb_top;
	struct mbuf	*mb_cur;
	char		*mb_pos;
	int		mb_count;
};
typedef struct mbdata mbdata_t;

struct smb_bitname {
	uint_t	bn_bit;
	char	*bn_name;
};
typedef struct smb_bitname smb_bitname_t;

extern int smb_debug, smb_verbose;
extern struct rcfile *smb_rc;

#ifdef __cplusplus
extern "C" {
#endif

int  smb_lib_init(void);
int  smb_open_driver(void);
int  smb_open_rcfile(struct smb_ctx *ctx);
void smb_error(const char *, int, ...);
char *smb_printb(char *, int, const struct smb_bitname *);

/*
 * Context management
 */
int  smb_ctx_init(struct smb_ctx *, int, char *[], int, int, int);
void smb_ctx_done(struct smb_ctx *);
int  smb_ctx_parseunc(struct smb_ctx *, const char *, int, const char **);
int  smb_ctx_setcharset(struct smb_ctx *, const char *);
int  smb_ctx_setfullserver(struct smb_ctx *, const char *);
void  smb_ctx_setserver(struct smb_ctx *, const char *);
int  smb_ctx_setuser(struct smb_ctx *, const char *, int);
int  smb_ctx_setshare(struct smb_ctx *, const char *, int);
int  smb_ctx_setscope(struct smb_ctx *, const char *);
int  smb_ctx_setworkgroup(struct smb_ctx *, const char *, int);
int  smb_ctx_setpassword(struct smb_ctx *, const char *, int);
int  smb_ctx_setsrvaddr(struct smb_ctx *, const char *);
int  smb_ctx_opt(struct smb_ctx *, int, const char *);
int  smb_ctx_findvc(struct smb_ctx *, int, int);
int  smb_ctx_negotiate(struct smb_ctx *, int, int, char *);
int  smb_ctx_tdis(struct smb_ctx *ctx);
int  smb_ctx_lookup(struct smb_ctx *, int, int);
int  smb_ctx_login(struct smb_ctx *);
int  smb_ctx_readrc(struct smb_ctx *);
int  smb_ctx_resolve(struct smb_ctx *);
int  smb_ctx_setflags(struct smb_ctx *, int, int, int);
int  smb_ctx_flags2(struct smb_ctx *);

int  smb_smb_open_print_file(struct smb_ctx *, int, int, const char *, smbfh*);
int  smb_smb_close_print_file(struct smb_ctx *, smbfh);

typedef void (*smb_ctx_close_hook_t)(struct smb_ctx *);
void smb_ctx_set_close_hook(smb_ctx_close_hook_t);
int  smb_fh_close(struct smb_ctx *ctx, smbfh fh);
int  smb_fh_open(struct smb_ctx *ctx, const char *, int, smbfh *);
int  smb_fh_read(struct smb_ctx *, smbfh, off_t, size_t, char *);
int  smb_fh_write(struct smb_ctx *, smbfh, off_t, size_t, const char *);
int  smb_fh_xactnp(struct smb_ctx *, smbfh, int, const char *,
	int *, char *, int *);

int  smb_t2_request(struct smb_ctx *, int, uint16_t *, const char *,
	int, void *, int, void *, int *, void *, int *, void *, int *);

void smb_simplecrypt(char *dst, const char *src);
int  smb_simpledecrypt(char *dst, const char *src);

int	nls_setrecode(const char *, const char *);
int	nls_setlocale(const char *);
char	*nls_str_toext(char *, const char *);
char	*nls_str_toloc(char *, const char *);
void	*nls_mem_toext(void *, const void *, int);
void	*nls_mem_toloc(void *, const void *, int);
char	*nls_str_upper(char *, const char *);
char	*nls_str_lower(char *, const char *);

int smb_get_authentication(char *, size_t, char *, size_t, char *, size_t,
	const char *, struct smb_ctx *);
int smb_browse(struct smb_ctx *, int);
void smb_save2keychain(struct smb_ctx *);
#define	smb_autherr(e) ((e) == EAUTH || (e) == EACCES || (e) == EPERM)
char *smb_strerror(int);
char *smb_getprogname();
#define	__progname smb_getprogname()

extern char *unpercent(char *component);

#ifdef __cplusplus
}
#endif

#endif /* _NETSMB_SMB_LIB_H_ */
