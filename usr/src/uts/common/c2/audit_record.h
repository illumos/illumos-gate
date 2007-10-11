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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _BSM_AUDIT_RECORD_H
#define	_BSM_AUDIT_RECORD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef _KERNEL
#include <sys/priv.h>
#else
#include <priv.h>
#endif
#include <sys/socket.h>
#include <sys/acl.h>

#include <sys/tsol/label.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Version of audit attributes
 *
 * OS Release      Version Number    Comments
 * ==========      ==============    ========
 * SunOS 5.1              2        Unbundled Package
 * SunOS 5.3              2        Bundled into the base OS
 * SunOS 5.4-5.x          2
 * Trusted Solaris 2.5    3        To distinguish potential new tokens
 * Trusted Solaris 7-8    4        Redefine X tokens that overlap with
 *                                 SunOS 5.7
 */

#define	TOKEN_VERSION   2

/*
 * Audit record token type codes
 */

/*
 * Control token types
 */

#define	AUT_INVALID		((char)0x00)
#define	AUT_OTHER_FILE		((char)0x11)
#define	AUT_OTHER_FILE32	AUT_OTHER_FILE
#define	AUT_OHEADER		((char)0x12)
#define	AUT_TRAILER		((char)0x13)
#define	AUT_HEADER		((char)0x14)
#define	AUT_HEADER32		AUT_HEADER
#define	AUT_HEADER32_EX		((char)0x15)
#define	AUT_TRAILER_MAGIC	((short)0xB105)

/*
 * Data token types
 */

#define	AUT_FMRI		((char)0x20)
#define	AUT_DATA		((char)0x21)
#define	AUT_IPC			((char)0x22)
#define	AUT_PATH		((char)0x23)
#define	AUT_SUBJECT		((char)0x24)
#define	AUT_SUBJECT32		AUT_SUBJECT
#define	AUT_XATPATH		((char)0x25)
#define	AUT_PROCESS		((char)0x26)
#define	AUT_PROCESS32		AUT_PROCESS
#define	AUT_RETURN		((char)0x27)
#define	AUT_RETURN32		AUT_RETURN
#define	AUT_TEXT		((char)0x28)
#define	AUT_OPAQUE		((char)0x29)
#define	AUT_IN_ADDR		((char)0x2A)
#define	AUT_IP			((char)0x2B)
#define	AUT_IPORT		((char)0x2C)
#define	AUT_ARG			((char)0x2D)
#define	AUT_ARG32		AUT_ARG
#define	AUT_SOCKET		((char)0x2E)
#define	AUT_SEQ			((char)0x2F)
#define	AUT_TID			((char)0x61)

/*
 * Modifier token types
 */

#define	AUT_ACL			((char)0x30)
#define	AUT_ATTR		((char)0x31)
#define	AUT_IPC_PERM		((char)0x32)
#define	AUT_LABEL		((char)0x33)
#define	AUT_GROUPS		((char)0x34)
/*
 * 0x35, 0x36, 0x37 unused
 */
#define	AUT_PRIV		((char)0x38)
#define	AUT_UPRIV		((char)0x39)
#define	AUT_LIAISON		((char)0x3A)
#define	AUT_NEWGROUPS		((char)0x3B)
#define	AUT_EXEC_ARGS		((char)0x3C)
#define	AUT_EXEC_ENV		((char)0x3D)
#define	AUT_ATTR32		((char)0x3E)
#define	AUT_UAUTH		((char)0x3F)
#define	AUT_ZONENAME		((char)0x60)

/*
 * X windows token types
 */

#define	AUT_XATOM		((char)0x40)
#define	AUT_XOBJ		((char)0x41)
#define	AUT_XPROTO		((char)0x42)
#define	AUT_XSELECT		((char)0x43)

#if	TOKEN_VERSION != 3
#define	AUT_XCOLORMAP		((char)0x44)
#define	AUT_XCURSOR		((char)0x45)
#define	AUT_XFONT		((char)0x46)
#define	AUT_XGC			((char)0x47)
#define	AUT_XPIXMAP		((char)0x48)
#define	AUT_XPROPERTY		((char)0x49)
#define	AUT_XWINDOW		((char)0x4A)
#define	AUT_XCLIENT		((char)0x4B)
#else	/* TOKEN_VERSION == 3 */
#define	AUT_XCOLORMAP		((char)0x74)
#define	AUT_XCURSOR		((char)0x75)
#define	AUT_XFONT		((char)0x76)
#define	AUT_XGC			((char)0x77)
#define	AUT_XPIXMAP		((char)0x78)
#define	AUT_XPROPERTY		((char)0x79)
#define	AUT_XWINDOW		((char)0x7A)
#define	AUT_XCLIENT		((char)0x7B)
#endif	/* TOKEN_VERSION != 3 */

/*
 * Command token types
 */

#define	AUT_CMD   		((char)0x51)
#define	AUT_EXIT   		((char)0x52)

/*
 * Miscellaneous token types
 */

#define	AUT_HOST		((char)0x70)

/*
 * Solaris64 token types
 */

#define	AUT_ARG64		((char)0x71)
#define	AUT_RETURN64		((char)0x72)
#define	AUT_ATTR64		((char)0x73)
#define	AUT_HEADER64		((char)0x74)
#define	AUT_SUBJECT64		((char)0x75)
#define	AUT_PROCESS64		((char)0x77)
#define	AUT_OTHER_FILE64	((char)0x78)

/*
 * Extended network address token types
 */

#define	AUT_HEADER64_EX		((char)0x79)
#define	AUT_SUBJECT32_EX	((char)0x7a)
#define	AUT_PROCESS32_EX	((char)0x7b)
#define	AUT_SUBJECT64_EX	((char)0x7c)
#define	AUT_PROCESS64_EX	((char)0x7d)
#define	AUT_IN_ADDR_EX		((char)0x7e)
#define	AUT_SOCKET_EX		((char)0x7f)


/*
 * Audit print suggestion types.
 */

#define	AUP_BINARY	((char)0)
#define	AUP_OCTAL	((char)1)
#define	AUP_DECIMAL	((char)2)
#define	AUP_HEX		((char)3)
#define	AUP_STRING	((char)4)

/*
 * Audit data member types.
 */

#define	AUR_BYTE	((char)0)
#define	AUR_CHAR	((char)0)
#define	AUR_SHORT	((char)1)
#define	AUR_INT		((char)2)
#define	AUR_INT32	((char)2)
#define	AUR_INT64	((char)3)

/*
 * Adr structures
 */

struct adr_s {
	char *adr_stream;	/* The base of the stream */
	char *adr_now;		/* The location within the stream */
};

typedef struct adr_s adr_t;


#ifdef _KERNEL

#include <sys/param.h>
#include <sys/systm.h>		/* for rval */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/user.h>
#include <sys/session.h>
#include <sys/ipc_impl.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <net/route.h>
#include <netinet/in_pcb.h>

/*
 * au_close flag arguments
 */

#define	AU_OK		0x1	/* Good audit record */
#define	AU_DONTBLOCK	0x2	/* Don't block or discard if queue full */
#define	AU_DEFER	0x4	/* Defer record queueing to syscall end */

/*
 * Audit token type is really an au_membuf pointer
 */
typedef au_buff_t token_t;
/*
 * token generation functions
 */
token_t *au_append_token(token_t *, token_t *);
token_t *au_set(caddr_t, uint_t);

void au_free_rec(au_buff_t *);

#define	au_getclr()		((token_t *)au_get_buff())
#define	au_toss_token(tok)	(au_free_rec((au_buff_t *)(tok)))

token_t *au_to_acl();
token_t *au_to_attr(struct vattr *);
token_t *au_to_data(char, char, char, char *);
token_t *au_to_header(int, au_event_t, au_emod_t);
token_t *au_to_header_ex(int, au_event_t, au_emod_t);
token_t *au_to_ipc(char, int);
token_t *au_to_ipc_perm(kipc_perm_t *);
token_t *au_to_iport(ushort_t);
token_t *au_to_in_addr(struct in_addr *);
token_t *au_to_in_addr_ex(int32_t *);
token_t *au_to_ip(struct ip *);
token_t *au_to_groups(const gid_t *, uint_t);
token_t *au_to_path(struct audit_path *);
token_t *au_to_seq();
token_t *au_to_process(uid_t, gid_t, uid_t, gid_t, pid_t,
			au_id_t, au_asid_t, const au_tid_addr_t *);
token_t *au_to_subject(uid_t, gid_t, uid_t, gid_t, pid_t,
			au_id_t, au_asid_t, const au_tid_addr_t *);
token_t *au_to_return32(int, int32_t);
token_t *au_to_return64(int, int64_t);
token_t *au_to_text(const char *);
/* token_t *au_to_tid(au_generic_tid_t *);  no kernel implementation */
token_t *au_to_trailer(int);
token_t *au_to_uauth(char *);
size_t	au_zonename_length(zone_t *);
token_t *au_to_zonename(size_t, zone_t *);
token_t *au_to_arg32(char, char *, uint32_t);
token_t *au_to_arg64(char, char *, uint64_t);
token_t *au_to_socket(struct socket *);
token_t *au_to_socket_ex(short, short, char *, char *);
token_t *au_to_sock_inet(struct sockaddr_in *);
token_t *au_to_exec_args(const char *, ssize_t);
token_t *au_to_exec_env(const char *, ssize_t);
token_t	*au_to_label(bslabel_t *);
token_t	*au_to_privset(const char *, const priv_set_t *, char, int);

void	au_uwrite();
void	au_close(au_kcontext_t *, caddr_t *, int, au_event_t, au_emod_t);
void	au_close_defer(token_t *, int, au_event_t, au_emod_t);
void	au_close_time(au_kcontext_t *, token_t *, int, au_event_t, au_emod_t,
	    timestruc_t *);
void	au_free_rec(au_buff_t *);
void	au_write(caddr_t *, token_t *);
void	au_mem_init(void);
void	au_zone_setup();
void	au_enqueue(au_kcontext_t *, au_buff_t *, adr_t *, adr_t *, int, int);
int	au_doorio(au_kcontext_t *);
int	au_doormsg(au_kcontext_t *, uint32_t, void *);
int	au_doio(struct vnode *, int);
int	au_token_size(token_t *);
int	au_append_rec(au_buff_t *, au_buff_t *, int);
int	au_append_buf(const char *, int, au_buff_t *);

#else /* !_KERNEL */

#include <limits.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ipc.h>

struct token_s {
	struct token_s	*tt_next;	/* Next in the list	*/
	short		tt_size;	/* Size of data		*/
	char		*tt_data;	/* The data		*/
};
typedef struct token_s token_t;

struct au_arg32_tok {
	uchar_t num;
	uint32_t val;
	ushort_t length;
	char *data;
};
typedef struct au_arg32_tok au_arg32_tok_t;

struct au_acl_tok {
	ulong_t type;
	ulong_t id;
	ulong_t mode;
};
typedef struct au_acl_tok au_acl_tok_t;

struct au_arg64_tok {
	uchar_t num;
	uint64_t val;
	ushort_t length;
	char *data;
};
typedef struct au_arg64_tok au_arg64_tok_t;

struct au_attr_tok {
	uint_t mode;
	uint_t uid;
	uint_t gid;
	int fs;
	int32_t node;
	uint32_t dev;
};
typedef struct au_attr_tok au_attr_tok_t;

struct au_attr32_tok {
	uint_t mode;
	uint_t uid;
	uint_t gid;
	int fs;
	int64_t node;
	uint32_t dev;
};
typedef struct au_attr32_tok au_attr32_tok_t;

struct au_attr64_tok {
	uint_t mode;
	uint_t uid;
	uint_t gid;
	int fs;
	int64_t node;
	uint64_t dev;
};
typedef struct au_attr64_tok au_attr64_tok_t;

struct au_data_tok {
	uchar_t pfmt;
	uchar_t size;
	uchar_t number;
	char *data;
};
typedef struct au_data_tok au_data_tok_t;

struct au_exit_tok {
	int status;
	int retval;
};
typedef struct au_exit_tok au_exit_tok_t;

struct au_file32_tok {
	/* really struct timeval from gettimeofday() */
	int32_t sec;		/* seconds since epoc */
	int32_t usec;		/* microseconds */
	ushort_t length;
	char *fname;
};
typedef struct au_file32_tok au_file32_tok_t;

struct au_file64_tok {
	/* really struct timeval */
	int64_t sec;		/* seconds since epoc */
	int64_t usec;		/* microseconds */
	ushort_t length;
	char *fname;
};
typedef struct au_file64_tok au_file64_tok_t;


struct au_groups_tok {
	gid_t groups[NGROUPS_MAX];
};
typedef struct au_groups_tok au_groups_tok_t;

struct au_header32_tok {
	uint_t length;
	uchar_t version;
	au_event_t event;
	ushort_t emod;
	/* really timestruct_t (struct timespec) from hrestime */
	int32_t sec;		/* seconds since epoc */
	int32_t nsec;		/* nanoseconds */
};
typedef struct au_header32_tok au_header32_tok_t;

struct au_header64_tok {
	uint_t length;
	uchar_t version;
	au_event_t event;
	ushort_t emod;
	/* really timestruct_t (struct timespec) from hrestime */
	int64_t sec;		/* seconds since epoc */
	int64_t nsec;		/* nanoseconds */
};
typedef struct au_header64_tok au_header64_tok_t;

struct au_inaddr_tok {
	struct in_addr ia;
};
typedef struct au_inaddr_tok au_inaddr_tok_t;

struct au_ip_tok {
	uchar_t version;
	struct ip ip;
};
typedef struct au_ip_tok au_ip_tok_t;

struct au_ipc_tok {
	key_t id;
};
typedef struct au_ipc_tok au_ipc_tok_t;

struct au_ipc_perm_tok {
	struct ipc_perm ipc_perm;
};
typedef struct au_ipc_perm_tok au_ipc_perm_tok_t;

struct au_iport_tok {
	ushort_t iport;
};
typedef struct au_iport_tok au_iport_tok_t;

struct au_invalid_tok {
	ushort_t length;
	char *data;
};
typedef struct au_invalid_tok au_invalid_tok_t;

struct au_opaque_tok {
	ushort_t length;
	char *data;
};
typedef struct au_opaque_tok au_opaque_tok_t;

struct au_path_tok {
	ushort_t length;
	char *name;
};
typedef struct au_path_tok au_path_tok_t;

struct au_tid32 {
	uint32_t port;
	uint32_t machine;
};
typedef struct au_tid32 au_tid32_t;

struct au_tid64 {
	uint64_t port;
	uint32_t machine;
};
typedef struct au_tid64 au_tid64_t;

struct au_proc32_tok {
	au_id_t auid;
	uid_t euid;
	gid_t egid;
	uid_t ruid;
	gid_t rgid;
	pid_t pid;
	pid_t sid;
	au_tid32_t tid;
};
typedef struct au_proc32_tok au_proc32_tok_t;

struct au_proc64_tok {
	au_id_t auid;
	uid_t euid;
	gid_t egid;
	uid_t ruid;
	gid_t rgid;
	pid_t pid;
	pid_t sid;
	au_tid64_t tid;
};
typedef struct au_proc64_tok au_proc64_tok_t;

struct au_ret32_tok {
	uchar_t error;
	uint32_t retval;
};
typedef struct au_ret32_tok au_ret32_tok_t;

struct au_ret64_tok {
	uchar_t error;
	uint64_t retval;
};
typedef struct au_ret64_tok au_ret64_tok_t;

struct au_seq_tok {
	uint_t num;
};
typedef struct au_seq_tok au_seq_tok_t;

struct au_socket_tok {
	short type;
	ushort_t lport;
	struct in_addr laddr;
	ushort_t fport;
	struct in_addr faddr;
};
typedef struct au_socket_tok au_socket_tok_t;

struct au_subj32_tok {
	au_id_t auid;
	uid_t euid;
	gid_t egid;
	uid_t ruid;
	gid_t rgid;
	pid_t pid;
	pid_t sid;
	au_tid32_t tid;
};
typedef struct au_subj32_tok au_subj32_tok_t;

struct au_subj64_tok {
	au_id_t auid;
	uid_t euid;
	gid_t egid;
	uid_t ruid;
	gid_t rgid;
	pid_t pid;
	pid_t sid;
	au_tid64_t tid;
};
typedef struct au_subj64_tok au_subj64_tok_t;

struct au_server_tok {
	au_id_t auid;
	uid_t euid;
	uid_t ruid;
	gid_t egid;
	pid_t pid;
};
typedef struct au_server_tok au_server_tok_t;

struct au_text_tok {
	ushort_t length;
	char *data;
};
typedef struct au_text_tok au_text_tok_t;

struct au_trailer_tok {
	ushort_t magic;
	uint_t length;
};
typedef struct au_trailer_tok au_trailer_tok_t;

struct au_uauth_tok {
	ushort_t length;
	char *data;
};
typedef struct au_uauth_tok au_uauth_tok_t;

struct au_token {
	char id;
	struct au_token *next;
	struct au_token *prev;
	char *data;
	ushort_t size;
	union {
		au_arg32_tok_t arg32;
		au_arg64_tok_t arg64;
		au_acl_tok_t acl;
		au_attr32_tok_t attr32;
		au_attr64_tok_t attr64;
		au_data_tok_t data;
		au_exit_tok_t exit;
		au_file32_tok_t file32;
		au_file64_tok_t file64;
		au_groups_tok_t groups;
		au_header32_tok_t header32;
		au_header64_tok_t header64;
		au_inaddr_tok_t inaddr;
		au_ip_tok_t ip;
		au_ipc_perm_tok_t ipc_perm;
		au_ipc_tok_t ipc;
		au_iport_tok_t iport;
		au_invalid_tok_t invalid;
		au_opaque_tok_t opaque;
		au_path_tok_t path;
		au_proc32_tok_t proc32;
		au_proc64_tok_t proc64;
		au_ret32_tok_t ret32;
		au_ret64_tok_t ret64;
		au_server_tok_t server;
		au_seq_tok_t seq;
		au_socket_tok_t socket;
		au_subj32_tok_t subj32;
		au_subj64_tok_t subj64;
		au_text_tok_t text;
		au_trailer_tok_t trailer;
		au_uauth_tok_t useofauth;
	} un;
};
typedef struct au_token au_token_t;


/*
 *	Old socket structure definition, formerly in <sys/socketvar.h>
 */
struct oldsocket {
	short	so_type;		/* generic type, see socket.h */
	short	so_options;		/* from socket call, see socket.h */
	short	so_linger;		/* time to linger while closing */
	short	so_state;		/* internal state flags SS_*, below */
	struct inpcb	*so_pcb;	/* protocol control block */
	struct	protosw *so_proto;	/* protocol handle */
/*
 * Variables for connection queueing.
 * Socket where accepts occur is so_head in all subsidiary sockets.
 * If so_head is 0, socket is not related to an accept.
 * For head socket so_q0 queues partially completed connections,
 * while so_q is a queue of connections ready to be accepted.
 * If a connection is aborted and it has so_head set, then
 * it has to be pulled out of either so_q0 or so_q.
 * We allow connections to queue up based on current queue lengths
 * and limit on number of queued connections for this socket.
 */
	struct	oldsocket *so_head;	/* back pointer to accept socket */
	struct	oldsocket *so_q0;	/* queue of partial connections */
	struct	oldsocket *so_q;	/* queue of incoming connections */
	short	so_q0len;		/* partials on so_q0 */
	short	so_qlen;		/* number of connections on so_q */
	short	so_qlimit;		/* max number queued connections */
	short	so_timeo;		/* connection timeout */
	ushort_t so_error;		/* error affecting connection */
	short	so_pgrp;		/* pgrp for signals */
	ulong_t	so_oobmark;		/* chars to oob mark */
/*
 * Variables for socket buffering.
 */
	struct	sockbuf {
		ulong_t	sb_cc;		/* actual chars in buffer */
		ulong_t	sb_hiwat;	/* max actual char count */
		ulong_t	sb_mbcnt;	/* chars of mbufs used */
		ulong_t	sb_mbmax;	/* max chars of mbufs to use */
		ulong_t	sb_lowat;	/* low water mark (not used yet) */
		struct	mbuf *sb_mb;	/* the mbuf chain */
		struct	proc *sb_sel;	/* process selecting read/write */
		short	sb_timeo;	/* timeout (not used yet) */
		short	sb_flags;	/* flags, see below */
	} so_rcv, so_snd;
/*
 * Hooks for alternative wakeup strategies.
 * These are used by kernel subsystems wishing to access the socket
 * abstraction.  If so_wupfunc is nonnull, it is called in place of
 * wakeup any time that wakeup would otherwise be called with an
 * argument whose value is an address lying within a socket structure.
 */
	struct wupalt	*so_wupalt;
};
extern token_t *au_to_arg32(char, char *, uint32_t);
extern token_t *au_to_arg64(char, char *, uint64_t);
extern token_t *au_to_acl(struct acl *);
extern token_t *au_to_attr(struct vattr *);
extern token_t *au_to_cmd(uint_t, char **, char **);
extern token_t *au_to_data(char, char, char, char *);
extern token_t *au_to_exec_args(char **);
extern token_t *au_to_exec_env(char **);
extern token_t *au_to_exit(int, int);
extern token_t *au_to_fmri(char *);
extern token_t *au_to_groups(int *);
extern token_t *au_to_newgroups(int, gid_t *);
extern token_t *au_to_header(au_event_t, au_emod_t);
extern token_t *au_to_header_ex(au_event_t, au_emod_t);
extern token_t *au_to_in_addr(struct in_addr *);
extern token_t *au_to_in_addr_ex(int32_t *);
extern token_t *au_to_ipc(char, int);
extern token_t *au_to_ipc_perm(struct ipc_perm *);
extern token_t *au_to_iport(ushort_t);
extern token_t *au_to_me(void);
extern token_t *au_to_mylabel(void);
extern token_t *au_to_opaque(char *, short);
extern token_t *au_to_path(char *);
extern token_t *au_to_privset(const char *, const priv_set_t *);
extern token_t *au_to_process(au_id_t, uid_t, gid_t, uid_t, gid_t,
				pid_t, au_asid_t, au_tid_t *);
extern token_t *au_to_process_ex(au_id_t, uid_t, gid_t, uid_t, gid_t,
				pid_t, au_asid_t, au_tid_addr_t *);
extern token_t *au_to_return32(char, uint32_t);
extern token_t *au_to_return64(char, uint64_t);
extern token_t *au_to_seq(int);
extern token_t *au_to_label(m_label_t *);
extern token_t *au_to_socket(struct oldsocket *);
extern token_t *au_to_subject(au_id_t, uid_t, gid_t, uid_t, gid_t,
				pid_t, au_asid_t, au_tid_t *);
extern token_t *au_to_subject_ex(au_id_t, uid_t, gid_t, uid_t, gid_t,
				pid_t, au_asid_t, au_tid_addr_t *);
extern token_t *au_to_text(char *);
extern token_t *au_to_tid(au_generic_tid_t *);
extern token_t *au_to_trailer(void);
extern token_t *au_to_uauth(char *);
extern token_t *au_to_upriv(char, char *);
extern token_t *au_to_xatom(char *);
extern token_t *au_to_xselect(char *, char *, char *);
extern token_t *au_to_xcolormap(int32_t, uid_t);
extern token_t *au_to_xcursor(int32_t, uid_t);
extern token_t *au_to_xfont(int32_t, uid_t);
extern token_t *au_to_xgc(int32_t, uid_t);
extern token_t *au_to_xpixmap(int32_t, uid_t);
extern token_t *au_to_xwindow(int32_t, uid_t);
extern token_t *au_to_xproperty(int32_t, uid_t, char *);
extern token_t *au_to_xclient(uint32_t);
extern token_t *au_to_zonename(char *);
#endif /* _KERNEL */

#ifdef	_KERNEL

void	adr_char(adr_t *, char *, int);
void	adr_int32(adr_t *, int32_t *, int);
void	adr_uint32(adr_t *, uint32_t *, int);
void	adr_int64(adr_t *, int64_t *, int);
void	adr_uint64(adr_t *, uint64_t *, int);
void	adr_short(adr_t *, short *, int);
void	adr_ushort(adr_t *, ushort_t *, int);
void	adr_start(adr_t *, char *);

char	*adr_getchar(adr_t *, char *);
char	*adr_getshort(adr_t *, short  *);
char	*adr_getushort(adr_t *, ushort_t  *);
char	*adr_getint32(adr_t *, int32_t *);
char	*adr_getuint32(adr_t *, uint32_t *);
char	*adr_getint64(adr_t *, int64_t *);
char	*adr_getuint64(adr_t *, uint64_t *);

int	adr_count(adr_t *);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _BSM_AUDIT_RECORD_H */
