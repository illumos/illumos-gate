/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBC_PORT_I18N_GETTEXT_H
#define	_LIBC_PORT_I18N_GETTEXT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <iconv.h>
#include <synch.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Type of MO file */
#define	T_SUN_MO	0x1
#define	T_GNU_MO	0x2
#define	T_GNU_SWAPPED_MO	0x4
#define	T_ILL_MO	0x8

#define	TP_BINDING	0
#define	TP_CODESET	1

/* Msg_g_node->flag */
#define	ST_CHK	0x1			/* header has been checked? */
#define	ST_SWP	0x2			/* reversed endian? */

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
	struct gnu_msg_info	*msg_file_info;	/* information of msg file */
	unsigned int	*hash_table; /* hash table */
	char	*src_encoding;	/* src encoding */
	char	*dst_encoding;	/* dst encoding */
	int	flag;				/* status */
	int	nplurals;			/* number of plural forms */
	plural_expr_t	plural;	/* plural expression */
	iconv_t	fd;				/* iconv descriptor */
	char	**conv_msgstr;	/* code-converted msgstr */
} Msg_g_node;

typedef struct msg_node {
	int	type;		/* T_SUN_MO, T_GNU_MO, or T_ILL_MO */
	int	trusted;	/* is this a trusted source? */
	char	*path;	/* name of message catalog */
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

typedef struct cache_node {
	unsigned int	hashid;	/* hashed valued for the locale name */
	Msg_node	*m_node;	/* link to Msg_node */
	Msg_node	*m_last;	/* link to the last Msg_node */
	Nls_node	*n_node;	/* link to Nls_node */
	Nls_node	*n_last;	/* link to the last Nls_node */
	struct cache_node	*next;	/* link to the next */
} Cache_node;

typedef struct {
	char	*cur_domain;	/* current domain */
	Dbinding	*dbind;		/* domain binding */
	Cache_node	*c_node;	/* link to the cache node */
	Cache_node	*c_last;	/* link to the last cache node */
	Msg_node	*c_m_node;	/* link to the current Msg_node */
	Nls_node	*c_n_node;	/* link to the current Nls_node */
} Gettext_t;

struct msg_pack {
	const char	*msgid1;	/* msgid1 argument */
	const char	*msgid2;	/* msgid2 argument */
	char	*msgfile;		/* msg catalog file to open */
	char	*domain;		/* textdomain name */
	char	*binding;		/* binding */
	char	*locale;		/* locale */
	char	*language;		/* LANGUAGE env */
	caddr_t	addr;			/* mmap'ed address */
	size_t	fsz;			/* file size */
	size_t	msgfile_len;	/* length of msgfile */
	size_t	domain_len;		/* length of domain */
	size_t	locale_len;		/* length of locale */

	unsigned int	n;		/* n argument */
	int	category;			/* category argument */
	int	plural;				/* plural or not */
	unsigned int	hash_locale;	/* hash ID of locale */
	int	nlsp;				/* nlsp */
	int	trusted;			/* trusted msg catalog or not */
};

struct cache_pack {
	int	cacheline;
	Msg_node	*mnp;
	Cache_node	*cnp;
	Cache_node	*node_hash;
};

#define	DEFAULT_DOMAIN		"messages"
#define	DEFAULT_DOMAIN_LEN	(sizeof (DEFAULT_DOMAIN) - 1)
#define	DEFAULT_BINDING		_DFLT_LOC_PATH
#define	MSGFILESUFFIX		".mo"
#define	MSGFILESUFFIXLEN	(sizeof (MSGFILESUFFIX) - 1)

#define	CURRENT_DOMAIN(gt)	(gt)->cur_domain
#define	FIRSTBIND(gt)	(gt)->dbind

#define	DFLTMSG(result, msgid1, msgid2, n, plural) \
	result = (plural ? \
		((n == 1) ? (char *)msgid1 : (char *)msgid2) : \
		(char *)msgid1)

#define	SWAP(p, ui32) \
	(((p)->flag & ST_SWP) ? doswap32(ui32) : (ui32))

extern const char	*defaultbind;
extern const char	default_domain[];
extern Gettext_t	*global_gt;

extern char *_textdomain_u(const char *, char *);
extern char *_real_bindtextdomain_u(const char *, const char *, int);
extern char *_real_gettext_u(const char *, const char *,
	const char *, unsigned long int, int, int);

extern int	setmsg(Msg_node *, char *, size_t);
extern char *handle_lang(struct cache_pack *, struct msg_pack *);
extern char *mk_msgfile(struct msg_pack *);
extern int check_cache(struct cache_pack *, struct msg_pack *);
extern void connect_entry(struct cache_pack *);
extern int connect_invalid_entry(struct cache_pack *, struct msg_pack *);
extern Msg_node *create_mnp(struct msg_pack *);
extern Cache_node *create_cnp(Msg_node *, struct msg_pack *);
extern void free_mnp_mp(Msg_node *, struct msg_pack *);
extern unsigned int	get_hashid(const char *, size_t *);
extern unsigned int	doswap32(unsigned int);

extern int	plural_expr(plural_expr_t *, const char *);
extern unsigned int	plural_eval(plural_expr_t, unsigned int);

extern char *gnu_key_2_text(Msg_g_node *, const char *,
	struct msg_pack *);

extern char *get_codeset(const char *);

#ifdef GETTEXT_DEBUG
extern void	printmp(struct msg_pack *, int);
extern void	printsunmsg(Msg_s_node *, int);
extern void	printgnumsg(Msg_g_node *, int);
extern void	printexpr(plural_expr_t, int);
extern void	printmnp(Msg_node *, int);
extern void	printcnp(Cache_node *, int);
extern void	printcp(struct cache_pack *, int);
extern void	printlist(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* !_LIBC_PORT_I18N_GETTEXT_H */
