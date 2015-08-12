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

#ifndef	_LIBC_PORT_I18N_GETTEXT_H
#define	_LIBC_PORT_I18N_GETTEXT_H

#include <sys/param.h>
#include <iconv.h>
#include <synch.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Type of MO file */
#define	T_MO_MASK		0x07
#define	T_SUN_MO		0x01
#define	T_GNU_MO		0x02
#define	T_ILL_MO		0x04

#define	T_GNU_MASK		0x300
#define	T_GNU_SWAPPED		0x100
#define	T_GNU_REV1		0x200

#define	TP_BINDING	0
#define	TP_CODESET	1

/* Msg_g_node->flag */
#define	ST_CHK	0x1			/* header has been checked? */
#define	ST_SWP	0x2			/* reversed endian? */
#define	ST_REV1	0x4			/* Revision 1 */

/*
 * msg_pack->status:
 * interaction between handle_lang() and handle_mo()
 */
#define	ST_GNU_MSG_FOUND	0x1	/* valid msg found in GNU MO */
#define	ST_GNU_MO_FOUND		0x2	/* GNU MO found */
#define	ST_SUN_MO_FOUND		0x4	/* Sun MO found */

typedef struct domain_binding {
	char	*domain;	/* domain name */
	char	*binding;	/* binding directory */
	char	*codeset;	/* codeset */
	struct domain_binding	*next;
} Dbinding;

/*
 * this structure is used for preserving nlspath templates before
 * passing them to bindtextdomain():
 */
typedef struct nlstmp {
	char	pathname[MAXPATHLEN];	/* the full pathname to file */
	size_t	len;			/* length of pathname */
	struct nlstmp	*next;		/* link to the next entry */
} Nlstmp;

typedef struct {
	struct msg_info	*msg_file_info;	/* information of msg file */
	struct msg_struct	*msg_list;	/* message list */
	char	*msg_ids;		/* actual message ids */
	char	*msg_strs;		/* actual message strs */
} Msg_s_node;

typedef struct expr	*plural_expr_t;

typedef struct {
	unsigned int	len;	/* length of the expanded str of macro */
	const char	*ptr;	/* pointer to the expanded str of macro */
} gnu_d_macro_t;

typedef struct {
	struct gnu_msg_info	*msg_file_info;
	struct gnu_msg_rev1_info	*rev1_header;
	size_t	fsize;			/* size of the GNU mo file */
	uint32_t	flag;		/* status */
	uint32_t	num_of_str;	/* number of static msgs */
	uint32_t	num_of_d_str;	/* number of dynamic msgs */
	uint32_t	hash_size;	/* hash table size  */
	uint32_t	*hash_table;	/* hash table */
	struct gnu_msg_ent	*msg_tbl[2]; 	/* msgid/str entries */
	struct gnu_msg_ent	*d_msg[2];	/* dynamic msgid/str entries */
	char	*mchunk;	/* pointer to memory chunk of dynamic strs */
	char	*src_encoding;	/* src encoding */
	char	*dst_encoding;	/* dst encoding */
	unsigned int	nplurals;	/* number of plural forms */
	plural_expr_t	plural;		/* plural expression */
	iconv_t	fd;			/* iconv descriptor */
	uint32_t	**conv_msgstr;	/* code-converted msgstr */
} Msg_g_node;

typedef struct msg_node {
	uint32_t	hashid;	/* hashed value of the domain name */
	uint16_t	type;	/* T_SUN_MO, T_GNU_MO, or T_ILL_MO */
	uint16_t	trusted;	/* is this a trusted source? */
	char	*path;		/* name of message catalog */
	union {
		Msg_s_node	*sunmsg;
		Msg_g_node	*gnumsg;
	} msg;
	struct msg_node	*next;	/* link to the next */
} Msg_node;

typedef struct nls_node {
	char	*domain;		/* key: domain name */
	char	*locale;		/* key: locale name */
	char	*nlspath;		/* key: NLSPATH */
	char	*ppaths;		/* value: expanded path */
	struct nls_node	*next;	/* link to the next */
} Nls_node;

typedef struct {
	char	*cur_domain;	/* current domain */
	Dbinding	*dbind;		/* domain binding */
	Msg_node	*m_node; 	/* link to the Msg_node cache */
	Nls_node	*n_node; 	/* link to the Nls_node cache */
	Msg_node	*c_m_node;	/* link to the current Msg_node */
	Nls_node	*c_n_node;	/* link to the current Nls_node */
} Gettext_t;

struct msg_pack {
	const char	*msgid1;	/* msgid1 argument */
	const char	*msgid2;	/* msgid2 argument */
	char	*msgfile;		/* msg catalog file to open */
	char	*domain;		/* textdomain name */
	char	*binding;		/* binding */
	const char	*locale;	/* locale */
	char	*language;		/* LANGUAGE env */
	caddr_t	addr;			/* mmap'ed address */
	size_t	fsz;			/* file size */
	uint32_t	hash_domain;	/* hash ID of domain */
	uint32_t	domain_len;	/* length of domain */
	unsigned int	n;		/* n argument */
	int	category;		/* category argument */
	int	plural;			/* plural or not */
	int	nlsp;			/* nlsp */
	int	trusted;		/* trusted msg catalog or not */
	int	status;			/* status */
};

#define	DEFAULT_DOMAIN		"messages"
#define	DEFAULT_BINDING		_DFLT_LOC_PATH
#define	MSGFILESUFFIX		".mo"
#define	MSGFILESUFFIXLEN	(sizeof (MSGFILESUFFIX) - 1)

#define	CURRENT_DOMAIN(gt)	(gt)->cur_domain
#define	FIRSTBIND(gt)	(gt)->dbind

#define	DFLTMSG(result, msgid1, msgid2, n, plural) \
	result = (plural ? \
		((n == 1) ? (char *)msgid1 : (char *)msgid2) : \
		(char *)msgid1)

#define	ROUND(m, s)	if ((m) % (s)) (m) += ((s) - ((m) % (s)))

#define	SWAP(p, ui32) \
	(((p)->flag & ST_SWP) ? doswap32(ui32) : (ui32))

#define	HASH_TBL(p, ui32)	\
	((((p)->flag & (ST_REV1|ST_SWP)) == ST_SWP) ? \
	    doswap32(ui32) : (ui32))

extern const char	*defaultbind;
extern const char	default_domain[];
extern Gettext_t	*global_gt;

extern char	*_textdomain_u(const char *, char *);
extern char	*_real_bindtextdomain_u(const char *, const char *, int);
extern char	*_real_gettext_u(const char *, const char *,
    const char *, unsigned long int, int, int, locale_t);
extern char	*handle_mo(struct msg_pack *);

extern int	gnu_setmsg(Msg_node *, char *, size_t);
extern char	*handle_lang(struct msg_pack *);
extern char	*mk_msgfile(struct msg_pack *);
extern Msg_node	*check_cache(struct msg_pack *);
extern uint32_t	get_hashid(const char *, uint32_t *);
extern uint32_t	doswap32(uint32_t);

extern int	plural_expr(plural_expr_t *, const char *);
extern unsigned int	plural_eval(plural_expr_t, unsigned int);

extern char	*gnu_key_2_text(Msg_g_node *, const char *, struct msg_pack *);

extern char	*get_codeset(const char *);

#ifdef GETTEXT_DEBUG
extern void	gprintf(int, const char *, ...);
extern void	printgt(Gettext_t *, int);
extern void	printmp(struct msg_pack *, int);
extern void	printsunmsg(Msg_s_node *, int);
extern void	printgnumsg(Msg_g_node *, int);
extern void	printexpr(plural_expr_t, int);
extern void	printmnp(Msg_node *, int);
extern void	printlist(void);
extern void	print_rev1_info(Msg_g_node *);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* !_LIBC_PORT_I18N_GETTEXT_H */
