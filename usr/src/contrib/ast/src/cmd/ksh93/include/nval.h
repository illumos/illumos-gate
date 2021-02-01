/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
#ifndef NV_DEFAULT
/*
 * David Korn
 * AT&T Labs
 *
 * Interface definitions of structures for name-value pairs
 * These structures are used for named variables, functions and aliases
 *
 */


#include	<ast.h>
#include	<cdt.h>
#include	<option.h>

/* for compatibility with old hash library */
#define Hashtab_t	Dt_t
#define HASH_BUCKET	1
#define HASH_NOSCOPE	2
#define HASH_SCOPE	4
#define hashscope(x)	dtvnext(x)

typedef struct Namval Namval_t;
typedef struct Namfun Namfun_t;
typedef struct Namdisc Namdisc_t;
typedef struct Nambfun Nambfun_t;
typedef struct Namarray Namarr_t;
typedef struct Namdecl Namdecl_t;

/*
 * This defines the template for nodes that have their own assignment
 * and or lookup functions
 */
struct Namdisc
{
	size_t	dsize;
	void	(*putval)(Namval_t*, const char*, int, Namfun_t*);
	char	*(*getval)(Namval_t*, Namfun_t*);
	Sfdouble_t	(*getnum)(Namval_t*, Namfun_t*);
	char	*(*setdisc)(Namval_t*, const char*, Namval_t*, Namfun_t*);
	Namval_t *(*createf)(Namval_t*, const char*, int, Namfun_t*);
	Namfun_t *(*clonef)(Namval_t*, Namval_t*, int, Namfun_t*);
	char	*(*namef)(Namval_t*, Namfun_t*);
	Namval_t *(*nextf)(Namval_t*, Dt_t*, Namfun_t*);
	Namval_t *(*typef)(Namval_t*, Namfun_t*);
	int	(*readf)(Namval_t*, Sfio_t*, int, Namfun_t*);
	int	(*writef)(Namval_t*, Sfio_t*, int, Namfun_t*);
};

struct Namfun
{
	const Namdisc_t	*disc;
	char		nofree;
	unsigned char	subshell;
	uint32_t	dsize;
	Namfun_t	*next;
	char		*last;
	Namval_t	*type;
};

struct Nambfun
{
	Namfun_t        fun;
	int		num;
	const char	**bnames;
	Namval_t	*bltins[1];
};

/* This is an array template header */
struct Namarray
{
	Namfun_t	hdr;
	long		nelem;				/* number of elements */
	void	*(*fun)(Namval_t*,const char*,int);	/* associative arrays */
	void		*fixed;			/* for fixed sized arrays */
	Dt_t		*table;			/* for subscripts */
	void		*scope;			/* non-zerp when scoped */
};

/* The context pointer for declaration command */
struct Namdecl
{
	Namval_t	*tp;			/* point to type */
	const char	*optstring;
	void		*optinfof;
};

/* attributes of name-value node attribute flags */

#define NV_DEFAULT 0
/* This defines the attributes for an attributed name-value pair node */
struct Namval
{
	Dtlink_t	nvlink;		/* space for cdt links */
	char		*nvname;	/* pointer to name of the node */
#if _ast_sizeof_pointer == 8
#   if _ast_intswap > 0
	unsigned short	nvflag; 	/* attributes */
	unsigned short	pad1;
#   else
	unsigned short	pad1;
	unsigned short	nvflag; 	/* attributes */
#   endif
	uint32_t  	nvsize;		/* size or base */
#else
	unsigned short	nvflag; 	/* attributes */
	unsigned short 	nvsize;		/* size or base */
#endif
#ifdef _NV_PRIVATE
	_NV_PRIVATE
#else
	Namfun_t	*nvfun;
	char		*nvalue;
	char		*nvprivate;
#endif /* _NV_PRIVATE */
};

#define NV_CLASS	".sh.type"
#define NV_DATA		"_"	/* special class or instance variable */
#define NV_MINSZ	(sizeof(struct Namval)-sizeof(Dtlink_t)-sizeof(char*))
#define nv_namptr(p,n)	((Namval_t*)((char*)(p)+(n)*NV_MINSZ-sizeof(Dtlink_t)))

/* The following attributes are for internal use */
#define NV_NOFREE	0x200	/* don't free the space when releasing value */
#define NV_ARRAY	0x400	/* node is an array */
#define NV_REF		0x4000	/* reference bit */
#define NV_TABLE	0x800	/* node is a dictionary table */
#define NV_IMPORT	0x1000	/* value imported from environment */
#define NV_MINIMAL	NV_IMPORT	/* node does not contain all fields */

#define NV_INTEGER	0x2	/* integer attribute */
/* The following attributes are valid only when NV_INTEGER is off */
#define NV_LTOU		0x4	/* convert to uppercase */
#define NV_UTOL		0x8	/* convert to lowercase */
#define NV_ZFILL	0x10	/* right justify and fill with leading zeros */
#define NV_RJUST	0x20	/* right justify and blank fill */
#define NV_LJUST	0x40	/* left justify and blank fill */
#define NV_BINARY	0x100	/* fixed size data buffer */
#define NV_RAW		NV_LJUST	/* used only with NV_BINARY */
#define NV_HOST		(NV_RJUST|NV_LJUST)	/* map to host filename */

/* The following attributes do not effect the value */
#define NV_RDONLY	0x1	/* readonly bit */
#define NV_EXPORT	0x2000	/* export bit */
#define NV_TAGGED	0x8000	/* user define tag bit */

/* The following are used with NV_INTEGER */
#define NV_SHORT	(NV_RJUST)	/* when integers are not long */
#define NV_LONG		(NV_UTOL)	/* for long long and long double */
#define NV_UNSIGN	(NV_LTOU)	/* for unsigned quantities */
#define NV_DOUBLE	(NV_INTEGER|NV_ZFILL)	/* for floating point */
#define NV_EXPNOTE	(NV_LJUST)	/* for scientific notation */
#define NV_HEXFLOAT	(NV_LTOU)	/* for C99 base16 float notation */

/*  options for nv_open */

#define NV_APPEND	0x10000		/* append value */
#define NV_MOVE		0x8000000	/* for use with nv_clone */
#define NV_ADD		8
					/* add node if not found */
#define NV_ASSIGN	NV_NOFREE	/* assignment is possible */
#define NV_NOASSIGN	0		/* backward compatibility */
#define NV_NOARRAY	0x200000	/* array name not possible */
#define NV_IARRAY	0x400000	/* for indexed array */
#define NV_NOREF	NV_REF		/* don't follow reference */
#define NV_IDENT	0x80		/* name must be identifier */
#define NV_VARNAME	0x20000		/* name must be ?(.)id*(.id) */
#define NV_NOADD	0x40000		/* do not add node */ 	
#define NV_NOSCOPE	0x80000		/* look only in current scope */
#define NV_NOFAIL	0x100000	/* return 0 on failure, no msg */
#define NV_NODISC	NV_IDENT	/* ignore disciplines */

#define NV_FUNCT	NV_IDENT	/* option for nv_create */
#define NV_BLTINOPT	NV_ZFILL	/* mark builtins in libcmd */

#define NV_PUBLIC	(~(NV_NOSCOPE|NV_ASSIGN|NV_IDENT|NV_VARNAME|NV_NOADD))

/* numeric types */
#define NV_INT16P	(NV_LJUST|NV_SHORT|NV_INTEGER)
#define NV_INT16	(NV_SHORT|NV_INTEGER)
#define NV_UINT16	(NV_UNSIGN|NV_SHORT|NV_INTEGER)
#define NV_UINT16P	(NV_LJUSTNV_UNSIGN|NV_SHORT|NV_INTEGER)
#define NV_INT32	(NV_INTEGER)
#define NV_UNT32	(NV_UNSIGN|NV_INTEGER)
#define NV_INT64	(NV_LONG|NV_INTEGER)
#define NV_UINT64	(NV_UNSIGN|NV_LONG|NV_INTEGER)
#define NV_FLOAT	(NV_SHORT|NV_DOUBLE)
#define NV_LDOUBLE	(NV_LONG|NV_DOUBLE)

/* name-value pair macros */
#define nv_isattr(np,f)		((np)->nvflag & (f))
#define nv_onattr(n,f)		((n)->nvflag |= (f))
#define nv_offattr(n,f)		((n)->nvflag &= ~(f))
#define nv_isarray(np)		(nv_isattr((np),NV_ARRAY))

/* The following are operations for associative arrays */
#define NV_AINIT	1	/* initialize */
#define NV_AFREE	2	/* free array */
#define NV_ANEXT	3	/* advance to next subscript */
#define NV_ANAME	4	/* return subscript name */
#define NV_ADELETE	5	/* delete current subscript */
#define NV_AADD		6	/* add subscript if not found */
#define NV_ACURRENT	7	/* return current subscript Namval_t* */
#define NV_ASETSUB	8	/* set current subscript */

/* The following are for nv_disc */
#define NV_FIRST	1
#define NV_LAST		2
#define NV_POP		3
#define NV_CLONE	4

/* The following are operations for nv_putsub() */
#define ARRAY_BITS	22
#define ARRAY_ADD	(1L<<ARRAY_BITS)	/* add subscript if not found */
#define	ARRAY_SCAN	(2L<<ARRAY_BITS)	/* For ${array[@]} */
#define ARRAY_UNDEF	(4L<<ARRAY_BITS)	/* For ${array} */


/* These  are disciplines provided by the library for use with nv_discfun */
#define NV_DCADD	0	/* used to add named disciplines */
#define NV_DCRESTRICT	1	/* variable that are restricted in rsh */

#if defined(__EXPORT__) && defined(_DLL)
#   ifdef _BLD_shell
#	define extern __EXPORT__
#   else
#	define extern __IMPORT__
#   endif /* _BLD_shell */
#endif /* _DLL */
/* prototype for array interface*/
extern Namarr_t	*nv_arrayptr(Namval_t*);
extern Namarr_t	*nv_setarray(Namval_t*,void*(*)(Namval_t*,const char*,int));
extern int	nv_arraynsub(Namarr_t*);
extern void	*nv_associative(Namval_t*,const char*,int);
extern int	nv_aindex(Namval_t*);
extern int	nv_nextsub(Namval_t*);
extern char	*nv_getsub(Namval_t*);
extern Namval_t	*nv_putsub(Namval_t*, char*, long);
extern Namval_t	*nv_opensub(Namval_t*);

/* name-value pair function prototypes */
extern int		nv_adddisc(Namval_t*, const char**, Namval_t**);
extern int		nv_clone(Namval_t*, Namval_t*, int);
extern void 		nv_close(Namval_t*);
extern void		*nv_context(Namval_t*);
extern Namval_t		*nv_create(const char*, Dt_t*, int,Namfun_t*);
extern void		nv_delete(Namval_t*, Dt_t*, int);
extern Dt_t		*nv_dict(Namval_t*);
extern Sfdouble_t	nv_getn(Namval_t*, Namfun_t*);
extern Sfdouble_t	nv_getnum(Namval_t*);
extern char 		*nv_getv(Namval_t*, Namfun_t*);
extern char 		*nv_getval(Namval_t*);
extern Namfun_t		*nv_hasdisc(Namval_t*, const Namdisc_t*);
extern int		nv_isnull(Namval_t*);
extern Namfun_t		*nv_isvtree(Namval_t*);
extern Namval_t		*nv_lastdict(void);
extern Namval_t		*nv_mkinttype(char*, size_t, int, const char*, Namdisc_t*);
extern void 		nv_newattr(Namval_t*,unsigned,int);
extern void 		nv_newtype(Namval_t*);
extern Namval_t		*nv_open(const char*,Dt_t*,int);
extern void 		nv_putval(Namval_t*,const char*,int);
extern void 		nv_putv(Namval_t*,const char*,int,Namfun_t*);
extern int		nv_rename(Namval_t*,int);
extern int		nv_scan(Dt_t*,void(*)(Namval_t*,void*),void*,int,int);
extern char 		*nv_setdisc(Namval_t*,const char*,Namval_t*,Namfun_t*);
extern void		nv_setref(Namval_t*, Dt_t*,int);
extern int		nv_settype(Namval_t*, Namval_t*, int);
extern void 		nv_setvec(Namval_t*,int,int,char*[]);
extern void		nv_setvtree(Namval_t*);
extern int 		nv_setsize(Namval_t*,int);
extern Namfun_t		*nv_disc(Namval_t*,Namfun_t*,int);
extern void 		nv_unset(Namval_t*);	 /*obsolete */
extern void 		_nv_unset(Namval_t*,int);
extern Namval_t		*nv_search(const char *, Dt_t*, int);
extern char		*nv_name(Namval_t*);
extern Namval_t		*nv_type(Namval_t*);
extern void		nv_addtype(Namval_t*,const char*, Optdisc_t*, size_t);
extern const Namdisc_t	*nv_discfun(int);

#ifdef _DLL
#   undef extern
#endif /* _DLL */

#define nv_unset(np)		_nv_unset(np,0)
#define nv_size(np)		nv_setsize((np),-1)
#define nv_stack(np,nf)		nv_disc(np,nf,0)

#if 0
/*
 * The names of many functions were changed in early '95
 * Here is a mapping to the old names
 */
#   define nv_istype(np)	nv_isattr(np)
#   define nv_newtype(np)	nv_newattr(np)
#   define nv_namset(np,a,b)	nv_open(np,a,b)
#   define nv_free(np)		nv_unset(np,0)
#   define nv_settype(np,a,b,c)	nv_setdisc(np,a,b,c)
#   define nv_search(np,a,b)	nv_open(np,a,((b)?0:NV_NOADD))
#   define settype	setdisc
#endif

#endif /* NV_DEFAULT */
