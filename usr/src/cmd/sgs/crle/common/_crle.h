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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__CRLE_H
#define	__CRLE_H

#include <sys/types.h>
#include <gelf.h>
#include <sgs.h>
#include <rtc.h>
#include <machdep.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Hash table support routines.
 */
typedef	struct hash_obj	Hash_obj;
typedef struct hash_ent Hash_ent;
typedef	struct hash_tbl	Hash_tbl;

typedef enum {
	HASH_STR,
	HASH_INT
} Hash_type;

/*
 * Each unique object (identified by dev/inode pair) is maintained as a hash
 * object.  This descriptor identifies the object (file or directory), whether
 * it has an alternate, or represents a non-existent object.
 */
struct hash_obj {
	Half		o_flags;		/* object identification */
	Hash_tbl	*o_tbl;			/* its dev/inode table */
	char		*o_alter;		/* any alternate path */
	Word		o_calter;		/*	and its conf offset */
	char		*o_path;		/* the objects real path */
	Lword		o_info;			/* information for cache */
						/*	consistency checks */
};

/*
 * Each element of a hash table is maintained as a hash entry.  Each element
 * points to a unique hash object.  Many elements can point to the same hash
 * object (as is the case with linked files).  Elements on the string table
 * hash lists identify their directory id, either the directory itself, or the
 * files that belong to the directory.  These directory and file entries are
 * what will be converted into object descriptors in the final cache file.
 */
struct hash_ent {
	Hash_ent	*e_next;		/* next hash item */
	Word		e_hash;			/* hash value (or inode no.) */
	Addr		e_key;			/* name (or inode no.) */
	int		e_off;			/* offset of file in dirname */
	Half		e_id;			/* directory identifier */
	Half		e_flags;		/* entry specific flags */
	Word		e_cnt;			/* no. of files in directory */
	Hash_ent	*e_dir;			/* files directory */
	Hash_ent	*e_path;		/* files full path entry */
	Hash_obj	*e_obj;			/* unique object */
	Rtc_obj		*e_cobj;		/* final configuration object */
};

/*
 * Each hash table is maintained as a hash table descriptor.  Each dev has a
 * hash table of inodes, and all directory and file entries are also maintained
 * on the string table hash table.
 */
struct hash_tbl {
	ulong_t		t_ident;		/* dev no. for inode cache */
	int		t_size;			/* no. of buckets */
	Hash_type	t_type;			/* HASH_INT or HASH_STR */
	Hash_ent	**t_entry;		/* entries */
};

#define	HASH_FND_ENT	0x01		/* search for existing hash entry */
#define	HASH_ADD_ENT	0x02		/* add hash entry */

/*
 * Environment variable support.
 */
typedef struct {
	const char	*e_str;		/* complete environment string */
	size_t		e_varsz;	/* variable size, ie. the LD_XXX part */
	size_t		e_totsz;	/* total string size */
	uint_t		e_flags;
} Env_desc;

/*
 * Filter/filtee association support.  The filtees are a list of Hash_ent's.
 */
typedef struct {
	Hash_ent	*f_fent;	/* filter */
	const char	*f_str;		/* filtee string and its associated */
	size_t		f_strsz;	/*	size */
	APlist		*f_filtee;	/* filtees */
} Flt_desc;

/*
 * Global data for final configuration files construction.
 */
typedef	struct crle_desc {
	char		*c_name;		/* calling program */
	char		*c_tempname;	/* temporary file, file descriptor */
	int		c_tempfd;	/*	mmapped address and size */
	Addr		c_tempaddr;
	size_t		c_tempsize;
	Addr		c_tempheadaddr;	/* Ptr to Rtc_head within c_tempaddr */
	char		*c_confil;	/* configuration file */
	char		*c_objdir;	/* current object directory for */
					/*	dldump(3C) */
	char		*c_audit;	/* audit library name */
	uint_t		c_flags;	/* state flags for crle processing */
	int		c_dlflags;	/* current dldump(3C) flags */
	int		c_strbkts;	/* internal hash table initialization */
	int		c_inobkts;	/*	parameters */
	uint_t		c_dirnum;	/* no. of directories processed */
	uint_t		c_filenum;	/* no. of files processed */
	uint_t		c_hashstrnum;	/* no. of hashed strings to create */
	Hash_tbl	*c_strtbl;	/* string table and size */
	size_t		c_strsize;
	APlist		*c_inotbls;	/* list of inode tables */
	const char	*c_app;		/* specific application */
	char		*c_edlibpath;	/* ELF default library path */
	char		*c_eslibpath;	/* ELF secure library path */
	APlist		*c_env;		/* environment variables */
	uint_t		c_envnum;	/*	and associated number */
	APlist		*c_flt;		/* filter/filtee associations */
	uint_t		c_fltrnum;	/*	and associated filter number */
	uint_t		c_fltenum;	/*	and associated filtee number */
} Crle_desc;

#define	CRLE_CREAT	0x0001		/* config file creation required */
#define	CRLE_ALTER	0x0002		/* alternative entries required */
#define	CRLE_DUMP	0x0004		/* alternative create by dldump(3C) */
#define	CRLE_ADDID	0x0008		/* Add Rtc_id to head of new files */
#define	CRLE_VERBOSE	0x0010		/* verbose mode */
/* 0x20 was previously used for a.out support */
#define	CRLE_EXISTS	0x0040		/* config file already exists */
#define	CRLE_DIFFDEV	0x0080		/* config file and temporary exist on */
					/*	different filesystems */
#define	CRLE_CONFDEF	0x0100		/* configuration file is default */
#define	CRLE_UPDATE	0x0200		/* update existing configuration file */
#define	CRLE_RPLENV	0x0400		/* replaceable environment variable */
#define	CRLE_PRMENV	0x0800		/* permanent environment variable */

#define	CRLE_EDLIB	0x1000		/* default elf search path supplied */
#define	CRLE_ESLIB	0x2000		/* default elf secure path supplied */

#define	AL_CNT_CRLE	10

/*
 * Return type code returned by inspectconfig()
 */
typedef enum {
	INSCFG_RET_OK = 0,		/* Config file is OK */
	INSCFG_RET_FAIL = 1,		/* Config file has a fatal problem */
	INSCFG_RET_NEED64 = 2,		/* 64-bit config seen by 32-bit crle */
} INSCFG_RET;

/*
 * Local functions.
 */
extern int		addlib(Crle_desc *, char **, const char *);
extern int		addenv(Crle_desc *, const char *, uint_t);
extern int		depend(Crle_desc *, const char *, Half, GElf_Ehdr *);
extern int		dlflags(Crle_desc *, const char *);
extern int		dump(Crle_desc *);
extern int		genconfig(Crle_desc *);
extern Hash_ent		*get_hash(Hash_tbl *, Addr, Half, int);
extern int		inspect(Crle_desc *, const char *, Half);
extern Hash_tbl		*make_hash(int, Hash_type, ulong_t);
extern INSCFG_RET	inspectconfig(Crle_desc *, int);
extern int		updateconfig(Crle_desc *);

#ifdef	__cplusplus
}
#endif

#endif	/* __CRLE_H */
