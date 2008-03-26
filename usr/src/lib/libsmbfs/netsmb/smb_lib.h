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

#ifndef _NETSMB_SMB_LIB_H_
#define	_NETSMB_SMB_LIB_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * These get/set macros do not handle mis-aligned data.
 * The data are all supposed to be aligned, but that's
 * up to the server.  If we ever encounter a server that
 * doesn't obey this rule, a "strict alignment" client
 * (i.e. SPARC) may get an alignment trap in one of these.
 * If that ever happens, make these macros into functions
 * that can handle mis-aligned data.  (Or catch traps.)
 */
#define	getb(buf, ofs) 		(((const uint8_t *)(buf))[ofs])
#define	setb(buf, ofs, val)	(((uint8_t *)(buf))[ofs]) = val
#define	getbw(buf, ofs)		((uint16_t)(getb(buf, ofs)))
#define	getw(buf, ofs)		(*((uint16_t *)(&((uint8_t *)(buf))[ofs])))
#define	getdw(buf, ofs)		(*((uint32_t *)(&((uint8_t *)(buf))[ofs])))

#ifdef _LITTLE_ENDIAN

#define	getwle(buf, ofs)	(*((uint16_t *)(&((uint8_t *)(buf))[ofs])))
#define	getdle(buf, ofs)	(*((uint32_t *)(&((uint8_t *)(buf))[ofs])))
#define	getwbe(buf, ofs)	(ntohs(getwle(buf, ofs)))
#define	getdbe(buf, ofs)	(ntohl(getdle(buf, ofs)))

#define	setwle(buf, ofs, val) getwle(buf, ofs) = val
#define	setwbe(buf, ofs, val) getwle(buf, ofs) = htons(val)
#define	setdle(buf, ofs, val) getdle(buf, ofs) = val
#define	setdbe(buf, ofs, val) getdle(buf, ofs) = htonl(val)

#else	/* _LITTLE_ENDIAN */

#define	getwbe(buf, ofs) (*((uint16_t *)(&((uint8_t *)(buf))[ofs])))
#define	getdbe(buf, ofs) (*((uint32_t *)(&((uint8_t *)(buf))[ofs])))
#define	getwle(buf, ofs) (BSWAP_16(getwbe(buf, ofs)))
#define	getdle(buf, ofs) (BSWAP_32(getdbe(buf, ofs)))

#define	setwbe(buf, ofs, val) getwbe(buf, ofs) = val
#define	setwle(buf, ofs, val) getwbe(buf, ofs) = BSWAP_16(val)
#define	setdbe(buf, ofs, val) getdbe(buf, ofs) = val
#define	setdle(buf, ofs, val) getdbe(buf, ofs) = BSWAP_32(val)

#endif	/* _LITTLE_ENDIAN */

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
#ifdef APPLE
	/* temporary automount hack */
	char	**ct_xxx;
	int	ct_maxxxx;	/* max # to mount (-x arg) */
#endif
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


/*
 * request handling structures
 */
struct mbuf {
	int		m_len;
	int		m_maxlen;
	char		*m_data;
	struct mbuf	*m_next;
};
typedef struct mbuf mbuf_t;

struct mbdata {
	struct mbuf	*mb_top;
	struct mbuf	*mb_cur;
	char		*mb_pos;
	int		mb_count;
};
typedef struct mbdata mbdata_t;

#define	M_ALIGNFACTOR	(sizeof (long))
#define	M_ALIGN(len)	(((len) + M_ALIGNFACTOR - 1) & ~(M_ALIGNFACTOR - 1))
#define	M_BASESIZE	(sizeof (struct mbuf))
#define	M_MINSIZE	(256 - M_BASESIZE)
#define	M_TOP(m)	((char *)(m) + M_BASESIZE)
#define	M_TRAILINGSPACE(m) ((m)->m_maxlen - (m)->m_len)
#define	mtod(m, t)	((t)(m)->m_data)

struct smb_rq {
	uchar_t		rq_cmd;
	struct mbdata	rq_rq;
	struct mbdata	rq_rp;
	struct smb_ctx *rq_ctx;
	int		rq_wcount;
	int		rq_bcount;
};
typedef struct smb_rq smb_rq_t;

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

struct sockaddr;

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

int  smb_read(struct smb_ctx *, smbfh, off_t, size_t, char *);
int  smb_write(struct smb_ctx *, smbfh, off_t, size_t, const char *);

#define	smb_rq_getrequest(rqp)	(&(rqp)->rq_rq)
#define	smb_rq_getreply(rqp)	(&(rqp)->rq_rp)

int  smb_rq_init(struct smb_ctx *, uchar_t, size_t, struct smb_rq **);
void smb_rq_done(struct smb_rq *);
void smb_rq_wend(struct smb_rq *);
int  smb_rq_simple(struct smb_rq *);
int  smb_rq_dmem(struct mbdata *, const char *, size_t);
int  smb_rq_dstring(struct mbdata *, const char *);

int  smb_t2_request(struct smb_ctx *, int, uint16_t *, const char *,
	int, void *, int, void *, int *, void *, int *, void *, int *);

void smb_simplecrypt(char *dst, const char *src);
int  smb_simpledecrypt(char *dst, const char *src);

int  m_getm(struct mbuf *, size_t, struct mbuf **);
int  m_lineup(struct mbuf *, struct mbuf **);
int  mb_init(struct mbdata *, size_t);
int  mb_initm(struct mbdata *, struct mbuf *);
int  mb_done(struct mbdata *);
int  mb_fit(struct mbdata *mbp, size_t size, char **pp);
int  mb_put_uint8(struct mbdata *, uint8_t);
int  mb_put_uint16be(struct mbdata *, uint16_t);
int  mb_put_uint16le(struct mbdata *, uint16_t);
int  mb_put_uint32be(struct mbdata *, uint32_t);
int  mb_put_uint32le(struct mbdata *, uint32_t);
int  mb_put_uint64be(struct mbdata *, uint64_t);
int  mb_put_uint64le(struct mbdata *, uint64_t);
int  mb_put_mem(struct mbdata *, const char *, size_t);
int  mb_put_pstring(struct mbdata *mbp, const char *s);
int  mb_put_mbuf(struct mbdata *, struct mbuf *);

int  mb_get_uint8(struct mbdata *, uint8_t *);
int  mb_get_uint16(struct mbdata *, uint16_t *);
int  mb_get_uint16le(struct mbdata *, uint16_t *);
int  mb_get_uint16be(struct mbdata *, uint16_t *);
int  mb_get_uint32(struct mbdata *, uint32_t *);
int  mb_get_uint32be(struct mbdata *, uint32_t *);
int  mb_get_uint32le(struct mbdata *, uint32_t *);
int  mb_get_uint64(struct mbdata *, uint64_t *);
int  mb_get_uint64be(struct mbdata *, uint64_t *);
int  mb_get_uint64le(struct mbdata *, uint64_t *);
int  mb_get_mem(struct mbdata *, char *, size_t);

extern uchar_t nls_lower[256], nls_upper[256];

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
