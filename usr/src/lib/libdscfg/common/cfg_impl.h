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

#ifndef	_CFG_IMPL_H
#define	_CFG_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#define	MAX_CFG		16	/* Max. number of lines in /etc/dscfg_format */

#define	CFG_MAX_KEY	256
#define	CFG_MAX_BUF	1024
#define	CFG_BLOCK_SIZE	512
#define	CFG_VTOC_SIZE	16
#define	CFG_VTOC_SKIP	CFG_VTOC_SIZE * CFG_BLOCK_SIZE

/*
 * Parser and file handling routines for Configuration parser.
 *
 *      General layout on disk
 *
 *      header                          cfgheader_t
 *      parser configuration            tag.field1.field2\n
 *      configuration data copy1        freeform strings
 *      configuration data copy2        freeform strings
 *
 * Strings in freeform fields are seperated by whitespace.
 * End of entry seperated by null.
 */

struct lookup {
	char		l_word[CFG_MAX_KEY];
	int		l_value;
	struct lookup	*l_next;
};

struct parser {
	struct lookup	tag;
	struct lookup	*fld;
	struct parser	*next;
};


/*
 * cfglist description
 *
 *                         ________
 *                        |        | the header has (with other things) an array
 *                        | header | of h_cfg[n].l_size entries. index 4
 *  disk layout           |        | contains cfp->cf_head->h_cfg[4].l_size.
 *                        |________|
 *        cfgfile-mapped->|        |
 * CFG_DEFAULT_PARSE_SIZE | parser | cache_hint.device.wrthru.nordcache.cnode
 *                        |        |
 *                        |________|
 * cfp->cf_head->h_ccopy1>|        |
 *   CFG_DEFAULT_SSIZE    |  data  | null terminated strings grouped together
 *                        | copy 1 | in order of cfglist offset. ie data at
 *                        |________| offset 0 is from h_cfgs[0].l_entry
 * cfp->cf_head->h_ccopy2>|        |
 *   CFG_DEFAULT_SSIZE    |  data  |
 *                        | copy 2 | same as above, used for two stage commit
 *                        |________|
 * cfp->cf_head->h_sizes1>|        | here is where lists of sizes go for each
 *   CFG_DEFAULT_PSIZE    | sizes  | cfglist. each array is preceded by the num
 *                        | copy 1 | of entries. |5|120|130|140|103|125|10|25 is
 *                        |________| a list with 5 entries 120,130,140,103,125
 * cfp->cf_head->h_sizes2>|        | these numbers are used to rebuild l_nentry
 *   CFG_DEFAULT_PSIZE    |  sizes | and l_esiz fields in h_cfg[n]
 *                        | copy 2 | this list is done as a two stage commit
 *                        |________|
 *
 *
 *
 * Data is read into cfp->cf_head->h_ccopy1 and cfp->cf_head->h_ccopy2
 * along with thier corresponding size metadata in cfp->cf_head->h_sizes1
 * and cfp->cf_head->h_sizes2. This infomation is used to rebuild the
 * cfglist structures seen below. The data in the cfglist structure is then
 * the ONLY valid data. Additions and/or deletions to the database is done
 * by moving around the cfglists and doing the right things with the size
 * arrays, the actual entries, total list sizes, the total of all the sizes of
 * all the cfglists and memory allocation. After addition/deletions are done,
 * and cfg_close is called, all of the lists are placed back into h_cparse
 * (which is really h_ccopy1 or h_ccopy2) the persistent lists are placed
 * into h_sizes (which is really h_sizes1 or h_sizes2).
 * A copy of each cfglist[n].l_size is kept in the header
 * (cfgheader->cfgsizes[n]).
 *
 *
 *
 *
 *		  h_cfgs        h_cfgs[3]
 *    head        |-[0]-   /|-l_name  == sndr
 *   	|-       /|-[1]-  / |-l_entry == host dev bmap host..ip sync '\0' ...
 * file |-      / |-[2]- /  |-l_esiz[0..l_nentry - 1] == [130, 132, 135, 133,..]
 *   |--|---------|-[3]---- |-l_enabled[0..l_nentry - 1] == [1,0,0,1,1]
 *	|-    	\ |-[4]- \  |-l_nentry == 5
 *	|-       \|-[5]-  \ |-l_index == 3
 *                |-[n]-   \|-l_free == 50537
 *			    |-l_size == 663 (130 + 132 + 135 + 133 + 133)
 *
 *
 *
 * l_name - is set when the parser is read.
 *	It is the first tag of a line of parser text.
 * l_entry - is a pointer to the beginning of the null terminated string
 * 	list that belongs to the cfglist tagged with l_name.
 * l_esiz - is a list of sizes of the strings contained in l_entry.
 * 	l_esiz[0] tells the size of the string at l_entry[0].
 *	l_esiz[n] is the size of the string that begins
 * 	at l_entry + l_esiz[0] + l_esiz[1]..+ l_esize[n - 1]
 * l_enabled - is a list of ones and zeros telling if this entry is alive
 * 	in the kernel. indexing is the same as l_esiz. (not implemented)
 * l_index - is the index of the parser tree that corresponds to l_name
 *	and is set when the parser tree is built
 * l_free - is how memory is managed. Memory is allocated on a
 *	DEFAULT_ENTRY_SIZE boundry.
 * 	the size of the balance of available memory at the end of l_entry
 *	is kept here. when this number is lower than the string we need to add,
 *	another block of memory is allocated for l_entry and the balance of
 *	the size is added to l_free.
 * l_size - is size of this list. It is the summation of l_esiz[0..n]
 *
 */

typedef struct cfglist {
	char	*l_name;	/* name of list sndr, ii.. */
	char	*l_entry;	/* start of list */
	int	*l_esiz;	/* array of sizes of entries */
	int	l_nentry;	/* number of entries */
	int 	l_index;	/* index in relation to parser position */
	uint_t	l_free;		/* num of characters available */
	int	l_size;		/* size of list */
} cfglist_t;

/* note: this does not imply DEFAULT_NENTRIES * DEFAULT_ENTRY_SIZE */
#define	DEFAULT_NENTRIES	100 /* value for l_esiz sizes array */
#define	DEFAULT_ENTRY_SIZE	(50 * CFG_MAX_BUF) /* 50K for each l_entry */


typedef struct cfgheader {
	int32_t	h_magic;
	int	h_state;	/* State flag see below */
	time_t	h_stamp;	/* time stamp of last update */
	long	h_lock;		/* lock for update */
	long	h_size;		/* total file size */
	int	h_parseoff;	/* parser config offset */
	int	h_parsesize;	/* parser config size */
	char	*h_cparse;	/* start of configuration  */
	int	h_csize;	/* size of config section */
	int	h_acsize; 	/* size of alternate config section */
	int 	*h_sizes;	/* sizes of lists */
	int	h_psize;	/* size of persistent section */
	int	h_apsize; 	/* size of alternate persistent section */
	char	*h_ccopy1;	/* base of config section 1 */
	char	*h_ccopy2;	/* base of config section 2 */
	int	*h_sizes1;	/* sizes of lists on disk 1 */
	int	*h_sizes2;	/* sizes of lists on disk 2 */
	int	h_seq1;		/* Sequenece number copy 1 both sections */
	int	h_seq2;		/* Sequenece number copy 2 both sections */
	char	h_ncfgs;	/* number of cfgs */
	cfglist_t *h_cfgs;	/* start of cfg lists */
	int	h_cfgsizes[MAX_CFG];	/* Sizes of configs */
} cfgheader_t;

#define	CFG_HDR_GOOD	0x1
#define	CFG_HDR_INVALID	0x2
#define	CFG_HDR_RDLOCK	0x4
#define	CFG_HDR_WRLOCK	0x8

struct cfg_io_s;		/* forward reference */
typedef	struct cfp {
	int	cf_fd;		/* file descriptor */
	int	cf_flag;	/* flags - see below */
	long	cf_size;	/* size of file in fbas */
	int	cf_lock;	/* lock file descriptor */
	char	*cf_mapped;	/* mapped location via mmap */
	char	*cf_name;	/* file name */
	cfgheader_t *cf_head;	/* header */
	struct cfg_io_s *cf_pp;	/* i/o provider */
} cfp_t;

typedef struct cfgfile {
	void	*cf_node;	/* node filter */
	cfp_t	cf[2];		/* local & optional cluster file */
} CFGFILE;

typedef struct cfg_io_s {
	struct cfg_io_s *next;			/* Link to next module */
	char	*name;				/* name of provider */
	cfp_t	*(*open)(cfp_t *, char *);	/* Open device */
	void	(*close)(cfp_t *);		/* Close device */
	int	(*seek)(cfp_t *, int, int);	/* Seek */
	int	(*read)(cfp_t *, void *, int);	/* read */
	int	(*write)(cfp_t *, void *, int);	/* write */
	char	*(*readcf)(cfp_t *, char *, int, int); /* Read mem config */
	int	(*addcf)(cfp_t *, char *, int); /* add to mem config */
	int	(*remcf)(cfp_t *, int, int);	/* remove an entry */
	int	(*replacecf)(cfp_t *, char *, int, int); /* replace entry */
} cfg_io_t;

#define	CFG_FILE	0x1	/* database is in a regular file */
#define	CFG_NOREWIND	0x4	/* don't rewind for each get_string */
#define	CFG_NOWRVTOC	0x8	/* sector starts in vtoc land, skip it */
#define	CFG_RDONLY	0x10	/* database is read only */

/*
 * constants
 */
#define	CFG_RDEV_LOCKFILE	"/var/tmp/.dscfg.lck"
#define	CFG_NEW_MAGIC		0x4d414749		/* MAGI */
#define	CFG_DEFAULT_PARSE_SIZE	(16 * 1024)
#define	CFG_DEFAULT_SSIZE	(2 * 1024 * 1024)
#define	CFG_DEFAULT_PSIZE	(512 * 1024)
#define	CFG_DEFAULT_OLDSIZE	(96 * 1024)
#define	CFG_CONFIG_SIZE		(CFG_DEFAULT_PARSE_SIZE + \
				(2 * CFG_DEFAULT_SSIZE) + \
				(2 * CFG_DEFAULT_PSIZE))
#ifdef	__cplusplus
}
#endif

#endif	/* _CFG_IMPL_H */
