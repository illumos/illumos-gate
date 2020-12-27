/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
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
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Phong Vo
 * Glenn Fowler
 * AT&T Research
 *
 * fts implementation unwound from the kpv ftwalk() of 1988-10-30
 */

#include <ast.h>
#include <ast_dir.h>
#include <error.h>
#include <fs3d.h>
#include <ls.h>

struct Ftsent;

typedef int (*Compar_f)(struct Ftsent* const*, struct Ftsent* const*);
typedef int (*Stat_f)(const char*, struct stat*);

#define _fts_status	status
#define _fts_statb	statb

#define _FTS_PRIVATE_ \
	FTSENT*		parent;			/* top parent		*/ \
	FTSENT*		todo;			/* todo list		*/ \
	FTSENT*		top;			/* top element		*/ \
	FTSENT*		root;						   \
	FTSENT*		bot;			/* bottom element	*/ \
	FTSENT*		free;			/* free element		*/ \
	FTSENT*		diroot;						   \
	FTSENT*		curdir;						   \
	FTSENT*		current;		/* current element	*/ \
	FTSENT*		previous;		/* previous current	*/ \
	FTSENT*		dotdot;						   \
	FTSENT*		link;			/* real current fts_link*/ \
	FTSENT*		pwd;			/* pwd parent		*/ \
	DIR*		dir;			/* current dir stream	*/ \
	Compar_f	comparf;		/* node comparison func	*/ \
	size_t		baselen;		/* current strlen(base)	*/ \
	size_t		homesize;		/* sizeof(home)		*/ \
	int		cd;			/* chdir status		*/ \
	int		cpname;						   \
	int		flags;			/* fts_open() flags	*/ \
	int		nd;						   \
	unsigned char	children;					   \
	unsigned char	fs3d;						   \
	unsigned char	nostat;					   	   \
	unsigned char	state;			/* fts_read() state	*/ \
	char*		base;			/* basename in path	*/ \
	char*		name;						   \
	char*		path;			/* path workspace	*/ \
	char*		home;			/* home/path buffer	*/ \
	char*		endbase;		/* space to build paths */ \
	char*		endbuf;			/* space to build paths */ \
	char*		pad[2];			/* $0.02 to splain this	*/

/*
 * NOTE: <ftwalk.h> relies on status and statb being the first two elements
 */

#define _FTSENT_PRIVATE_ \
	int		nd;			/* popdir() count	*/ \
	FTSENT*		left;			/* left child		*/ \
	FTSENT*		right;			/* right child		*/ \
	FTSENT*		pwd;			/* pwd parent		*/ \
	FTSENT*		stack;			/* getlist() stack	*/ \
	long		nlink;			/* FTS_D link count	*/ \
	unsigned char	must;			/* must stat		*/ \
	unsigned char	type;			/* DT_* type		*/ \
	unsigned char	symlink;		/* originally a symlink	*/ \
	char		name[sizeof(int)];	/* fts_name data	*/

#include <fts.h>

#ifndef ENOSYS
#define ENOSYS		EINVAL
#endif


#if MAXNAMLEN > 16
#define MINNAME		32
#else
#define MINNAME		16
#endif

#define drop(p,f)	(((f)->fts_namelen < MINNAME) ? ((f)->fts_link = (p)->free, (p)->free = (f)) : (free(f), (p)->free))

#define ACCESS(p,f)	((p)->cd==0?(f)->fts_name:(f)->fts_path)
#define PATH(f,p,l)	((!((f)->flags&FTS_SEEDOTDIR)&&(l)>0&&(p)[0]=='.'&&(p)[1]=='/')?((p)+2):(p))
#define SAME(one,two)	((one)->st_ino==(two)->st_ino&&(one)->st_dev==(two)->st_dev)
#define SKIPLINK(p,f)	((f)->fts_parent->nlink == 0)

#ifdef D_TYPE
#define ISTYPE(f,t)	((f)->type == (t))
#define TYPE(f,t)	((f)->type = (t))
#define SKIP(p,f)	((f)->fts_parent->must == 0 && (((f)->type == DT_UNKNOWN) ? SKIPLINK(p,f) : ((f)->type != DT_DIR && ((f)->type != DT_LNK || ((p)->flags & FTS_PHYSICAL)))))
#else
#undef	DT_UNKNOWN
#define DT_UNKNOWN	0
#undef	DT_LNK
#define DT_LNK		1
#define ISTYPE(f,t)	((t)==DT_UNKNOWN)
#define TYPE(f,d)
#define SKIP(p,f)	((f)->fts_parent->must == 0 && SKIPLINK(p,f))
#endif

#ifndef D_FILENO
#define D_FILENO(d)	(1)
#endif

/*
 * NOTE: a malicious dir rename() could change .. underfoot so we
 *	 must always verify; undef verify to enable the unsafe code
 */

#define verify		1

/*
 * FTS_NOSTAT requires a dir with
 *	D_TYPE(&dirent_t)!=DT_UNKNOWN
 *	    OR
 *	st_nlink>=2
 */

#define FTS_children_resume	1
#define FTS_children_return	2
#define FTS_error		3
#define FTS_popstack		4
#define FTS_popstack_resume	5
#define FTS_popstack_return	6
#define FTS_preorder		7
#define FTS_preorder_resume	8
#define FTS_preorder_return	9
#define FTS_readdir		10
#define FTS_terminal		11
#define FTS_todo		12
#define FTS_top_return		13

typedef int (*Notify_f)(FTS*, FTSENT*, void*);

typedef struct Notify_s
{
	struct Notify_s*	next;
	Notify_f		notifyf;
	void*			context;
} Notify_t;

static Notify_t*		notify;

/*
 * allocate an FTSENT node
 */

static FTSENT*
node(FTS* fts, FTSENT* parent, register char* name, register size_t namelen)
{
	register FTSENT*	f;
	register size_t		n;

	if (fts->free && namelen < MINNAME)
	{
		f = fts->free;
		fts->free = f->fts_link;
	}
	else
	{
		n = (namelen < MINNAME ? MINNAME : namelen + 1) - sizeof(int);
		if (!(f = newof(0, FTSENT, 1, n)))
		{
			fts->fts_errno = errno;
			fts->state = FTS_error;
			return 0;
		}
		f->fts = fts;
	}
	TYPE(f, DT_UNKNOWN);
	f->status = 0;
	f->symlink = 0;
	f->fts_level = (f->fts_parent = parent)->fts_level + 1;
#if __OBSOLETE__ < 20140101
	f->_fts_level = (short)f->fts_level;
#endif
	f->fts_link = 0;
	f->fts_pointer = 0;
	f->fts_number = 0;
	f->fts_errno = 0;
	f->fts_namelen = namelen;
#if __OBSOLETE__ < 20140101
	f->_fts_namelen = (unsigned short)f->fts_namelen;
#endif
	f->fts_name = f->name;
	f->fts_statp = &f->statb;
	memcpy(f->fts_name, name, namelen + 1);
	return f;
}

/*
 * compare directories by device/inode
 */

static int
statcmp(FTSENT* const* pf1, FTSENT* const* pf2)
{
	register const FTSENT*	f1 = *pf1;
	register const FTSENT*	f2 = *pf2;

	if (f1->statb.st_ino < f2->statb.st_ino)
		return -1;
	if (f1->statb.st_ino > f2->statb.st_ino)
		return 1;
	if (f1->statb.st_dev < f2->statb.st_dev)
		return -1;
	if (f1->statb.st_dev > f2->statb.st_dev)
		return 1;

	/*
	 * hack for NFS where <dev,ino> may not uniquely identify objects
	 */

	if (f1->statb.st_mtime < f2->statb.st_mtime)
		return -1;
	if (f1->statb.st_mtime > f2->statb.st_mtime)
		return 1;
	return 0;
}

/*
 * search trees with top-down splaying (a la Tarjan and Sleator)
 * when used for insertion sort, this implements a stable sort
 */

#define RROTATE(r)	(t = r->left, r->left = t->right, t->right = r, r = t)
#define LROTATE(r)	(t = r->right, r->right = t->left, t->left = r, r = t)

static FTSENT*
search(FTSENT* e, FTSENT* root, int(*comparf)(FTSENT* const*, FTSENT* const*), int insert)
{
	register int		cmp;
	register FTSENT*	t;
	register FTSENT*	left;
	register FTSENT*	right;
	register FTSENT*	lroot;
	register FTSENT*	rroot;

	left = right = lroot = rroot = 0;
	while (root)
	{
		if (!(cmp = (*comparf)(&e, &root)) && !insert)
			break;
		if (cmp < 0)
		{	
			/*
			 * this is the left zig-zig case
			 */

			if (root->left && (cmp = (*comparf)(&e, &root->left)) <= 0)
			{
				RROTATE(root);
				if (!cmp && !insert)
					break;
			}

			/*
			 * stick all things > e to the right tree
			 */

			if (right)
				right->left = root;
			else
				rroot = root;
			right = root;
			root = root->left;
			right->left = 0;
		}
		else
		{	
			/*
			 * this is the right zig-zig case
			 */

			if (root->right && (cmp = (*comparf)(&e, &root->right)) >= 0)
			{
				LROTATE(root);
				if (!cmp && !insert)
					break;
			}

			/*
			 * stick all things <= e to the left tree
			 */

			if (left)
				left->right = root;
			else
				lroot = root;
			left = root;
			root = root->right;
			left->right = 0;
		}
	}
	if (!root)
		root = e;
	else
	{
		if (right)
			right->left = root->right;
		else
			rroot = root->right;
		if (left)
			left->right = root->left;
		else
			lroot = root->left;
	}
	root->left = lroot;
	root->right = rroot;
	return root;
}

/*
 * delete the root element from the tree
 */

static FTSENT*
deleteroot(register FTSENT* root)
{
	register FTSENT*	t;
	register FTSENT*	left;
	register FTSENT*	right;

	right = root->right;
	if (!(left = root->left))
		root = right;
	else
	{
		while (left->right)
			LROTATE(left);
		left->right = right;
		root = left;
	}
	return root;
}

/*
 * generate ordered fts_link list from binary tree at root
 * FTSENT.stack instead of recursion to avoid blowing the real
 * stack on big directories
 */

static void
getlist(register FTSENT** top, register FTSENT** bot, register FTSENT* root)
{
	register FTSENT*	stack = 0;

	for (;;)
	{
		if (root->left)
		{
			root->stack = stack;
			stack = root;
			root = root->left;
		}
		else
		{
			for (;;)
			{
				if (*top)
					*bot = (*bot)->fts_link = root;
				else
					*bot = *top = root;
				if (root->right)
				{
					root = root->right;
					break;
				}
				if (!(root = stack))
				{
					(*bot)->fts_link = 0;
					return;
				}
				stack = stack->stack;
			}
		}
	}
}

/*
 * set directory when curdir is lost in space
 */

static int
setdir(register char* home, register char* path)
{
	register int	cdrv;

	if (path[0] == '/')
		cdrv = pathcd(path, NiL);
	else
	{
		/*
		 * note that path and home are in the same buffer
		 */

		path[-1] = '/';
		cdrv = pathcd(home, NiL);
		path[-1] = 0;
	}
	if (cdrv < 0)
		pathcd(home, NiL);
	return cdrv;
}

/*
 * set to parent dir
 */

static int
setpdir(register char* home, register char* path, register char* base)
{
	register int	c;
	register int	cdrv;

	if (base > path)
	{
		c = base[0];
		base[0] = 0;
		cdrv = setdir(home, path);
		base[0] = c;
	}
	else
		cdrv = pathcd(home, NiL);
	return cdrv;
}

/*
 * pop a set of directories
 */
static int
popdirs(FTS* fts)
{
	register FTSENT*f;
	register char*	s;
	register char*	e;
#ifndef verify
	register int	verify;
#endif
	struct stat	sb;
	char		buf[PATH_MAX];

	if (!(f = fts->curdir) || f->fts_level < 0)
		return -1;
	e = buf + sizeof(buf) - 4;
#ifndef verify
	verify = 0;
#endif
	while (fts->nd > 0)
	{
		for (s = buf; s < e && fts->nd > 0; fts->nd--)
		{
			if (fts->pwd)
			{
#ifndef verify
				verify |= fts->pwd->symlink;
#endif
				fts->pwd = fts->pwd->pwd;
			}
			*s++ = '.';
			*s++ = '.';
			*s++ = '/';
		}
		*s = 0;
		if (chdir(buf))
			return -1;
	}
	return (verify && (stat(".", &sb) < 0 || !SAME(&sb, f->fts_statp))) ? -1 : 0;
}

/*
 * initialize st from path and fts_info from st
 */

static int
info(FTS* fts, register FTSENT* f, const char* path, struct stat* sp, int flags)
{
	if (path)
	{
#ifdef S_ISLNK
		if (!f->symlink && (ISTYPE(f, DT_UNKNOWN) || ISTYPE(f, DT_LNK)))
		{
			if (lstat(path, sp) < 0)
				goto bad;
		}
		else
#endif
			if (stat(path, sp) < 0)
				goto bad;
	}
#ifdef S_ISLNK
 again:
#endif
	if (S_ISDIR(sp->st_mode))
	{
		if ((flags & FTS_NOSTAT) && !fts->fs3d)
		{
			f->fts_parent->nlink--;
#ifdef D_TYPE
			if ((f->nlink = sp->st_nlink) < 2)
			{
				f->must = 2;
				f->nlink = 2;
			}
			else
				f->must = 0;
#else
			if ((f->nlink = sp->st_nlink) >= 2)
				f->must = 1;
			else
				f->must = 2;
#endif
		}
		else
			f->must = 2;
		TYPE(f, DT_DIR);
		f->fts_info = FTS_D;
	}
#ifdef S_ISLNK
	else if (S_ISLNK((sp)->st_mode))
	{
		struct stat	sb;

		f->symlink = 1;
		if (flags & FTS_PHYSICAL)
		{
			TYPE(f, DT_LNK);
			f->fts_info = FTS_SL;
		}
		else if (stat(path, &sb) >= 0)
		{
			*sp = sb;
			flags = FTS_PHYSICAL;
			goto again;
		}
		else
		{
			TYPE(f, DT_LNK);
			f->fts_info = FTS_SLNONE;
		}
	}
#endif
	else
	{
		TYPE(f, DT_REG);
		f->fts_info = FTS_F;
	}
	return 0;
 bad:
	TYPE(f, DT_UNKNOWN);
	f->fts_info = FTS_NS;
	return -1;
}

/*
 * get top list of elements to process
 * ordering delayed until first fts_read()
 * to give caller a chance to set fts->handle
 */

static FTSENT*
toplist(FTS* fts, register char* const* pathnames)
{
	register char*		path;
	register FTSENT*	f;
	register FTSENT*	top;
	register FTSENT*	bot;
	int			physical;
	int			metaphysical;
	char*			s;
	struct stat		st;

	if (fts->flags & FTS_NOSEEDOTDIR)
		fts->flags &= ~FTS_SEEDOTDIR;
	physical = (fts->flags & FTS_PHYSICAL);
	metaphysical = (fts->flags & (FTS_META|FTS_PHYSICAL)) == (FTS_META|FTS_PHYSICAL);
	top = bot = 0;
	while (path = *pathnames++)
	{
		/*
		 * make elements
		 */

		if (!(f = node(fts, fts->parent, path, strlen(path))))
			break;
		path = f->fts_name;
		if (!physical)
			f->fts_namelen = (fts->flags & FTS_SEEDOTDIR) ? strlen(path) : (pathcanon(path, strlen(path) + 1, 0) - path);
		else if (*path != '.')
		{
			f->fts_namelen = strlen(path);
			fts->flags |= FTS_SEEDOTDIR;
		}
		else
		{
			if (fts->flags & FTS_NOSEEDOTDIR)
			{
				fts->flags &= ~FTS_SEEDOTDIR;
				s = path;
				while (*s++ == '.' && *s++ == '/')
				{
					while (*s == '/')
						s++;
					if (!*s)
						break;
					path = f->fts_name;
					while (*path++ = *s++);
					path = f->fts_name;
				}
			}
			else
				fts->flags |= FTS_SEEDOTDIR;
			for (s = path + strlen(path); s > path && *(s - 1) == '/'; s--);
			*s = 0;
			f->fts_namelen = s - path;
		}
#if __OBSOLETE__ < 20140101
		f->_fts_namelen = (unsigned short)f->fts_namelen;
#endif
		if (!*path)
		{
			errno = ENOENT;
			f->fts_info = FTS_NS;
		}
		else
			info(fts, f, path, f->fts_statp, fts->flags);
#ifdef S_ISLNK

		/*
		 * don't let any standards committee get
		 * away with calling your idea a hack
		 */

		if (metaphysical && f->fts_info == FTS_SL)
		{
			if (stat(path, &st) >= 0)
			{
				*f->fts_statp = st;
				info(fts, f, NiL, f->fts_statp, 0);
			}
			else
				f->fts_info = FTS_SLNONE;
		}
#endif
		if (bot)
		{
			bot->fts_link = f;
			bot = f;
		}
		else
			top = bot = f;
	}
	return top;
}

/*
 * order fts->todo if fts->comparf != 0
 */

static void
order(FTS* fts)
{
	register FTSENT*	f;
	register FTSENT*	root;
	FTSENT*			top;
	FTSENT*			bot;

	top = bot = root = 0;
	for (f = fts->todo; f; f = f->fts_link)
		root = search(f, root, fts->comparf, 1);
	getlist(&top, &bot, root);
	fts->todo = top;
}

/*
 * resize the path buffer
 * note that free() is not used because we may need to chdir(fts->home)
 * if there isn't enough space to continue
 */

static int
resize(register FTS* fts, size_t inc)
{
	register char*	old;
	register char*	newp;
	register size_t	n_old;

	/*
	 * add space for "/." used in testing FTS_DNX
	 */

	n_old = fts->homesize;
	fts->homesize = ((fts->homesize + inc + 4) / PATH_MAX + 1) * PATH_MAX;
	if (!(newp = newof(0, char, fts->homesize, 0)))
	{
		fts->fts_errno = errno;
		fts->state = FTS_error;
		return -1;
	}
	old = fts->home;
	fts->home = newp;
	memcpy(newp, old, n_old);
	if (fts->endbuf)
		fts->endbuf = newp + fts->homesize - 4;
	if (fts->path)
		fts->path = newp + (fts->path - old);
	if (fts->base)
		fts->base = newp + (fts->base - old);
	free(old);
	return 0;
}

/*
 * open a new fts stream on pathnames
 */

FTS*
fts_open(char* const* pathnames, int flags, int (*comparf)(FTSENT* const*, FTSENT* const*))
{
	register FTS*	fts;

	if (!(fts = newof(0, FTS, 1, sizeof(FTSENT))))
		return 0;
	fts->flags = flags;
	fts->cd = (flags & FTS_NOCHDIR) ? 1 : -1;
	fts->comparf = comparf;
	fts->fs3d = fs3d(FS3D_TEST);

	/*
	 * set up the path work buffer
	 */

	fts->homesize = 2 * PATH_MAX;
	for (;;)
	{
		if (!(fts->home = newof(fts->home, char, fts->homesize, 0)))
		{
			free(fts);
			return 0;
		}
		if (fts->cd > 0 || getcwd(fts->home, fts->homesize))
			break;
		if (errno == ERANGE)
			fts->homesize += PATH_MAX;
		else
			fts->cd = 1;
	}
	fts->endbuf = fts->home + fts->homesize - 4;

	/*
	 * initialize the tippity-top
	 */

	fts->parent = (FTSENT*)(fts + 1);
	fts->parent->fts_info = FTS_D;
	memcpy(fts->parent->fts_accpath = fts->parent->fts_path = fts->parent->fts_name = fts->parent->name, ".", 2);
	fts->parent->fts_level = -1;
#if __OBSOLETE__ < 20140101
	fts->parent->_fts_level = (short)fts->parent->fts_level;
#endif
	fts->parent->fts_statp = &fts->parent->statb;
	fts->parent->must = 2;
	fts->parent->type = DT_UNKNOWN;
	fts->path = fts->home + strlen(fts->home) + 1;

	/*
	 * make the list of top elements
	 */

	if (!pathnames || (flags & FTS_ONEPATH) || !*pathnames)
	{
		char*	v[2];

		v[0] = pathnames && (flags & FTS_ONEPATH) ? (char*)pathnames : ".";
		v[1] = 0;
		fts->todo = toplist(fts, v);
	}
	else
		fts->todo = toplist(fts, pathnames);
#if _HUH_1997_01_07
	if (!fts->todo || fts->todo->fts_info == FTS_NS && !fts->todo->fts_link)
#else
	if (!fts->todo)
#endif
	{
		fts_close(fts);
		return 0;
	}
	return fts;
}

/*
 * return the next FTS entry
 */

FTSENT*
fts_read(register FTS* fts)
{
	register char*		s;
	register int		n;
	register FTSENT*	f;
	struct dirent*		d;
	size_t			i;
	FTSENT*			t;
	Notify_t*		p;
#ifdef verify
	struct stat		sb;
#endif

	for (;;)
		switch (fts->state)
		{

		case FTS_top_return:

			f = fts->todo;
			t = 0;
			while (f)
				if (f->status == FTS_SKIP)
				{
					if (t)
					{
						t->fts_link = f->fts_link;
						drop(fts, f);
						f = t->fts_link;
					}
					else
					{
						fts->todo = f->fts_link;
						drop(fts, f);
						f = fts->todo;
					}
				}
				else
				{
					t = f;
					f = f->fts_link;
				}
			/*FALLTHROUGH*/

		case 0:

			if (!fts->state && fts->comparf)
				order(fts);
			if (!(f = fts->todo))
				return 0;
			/*FALLTHROUGH*/

		case FTS_todo:

			/*
			 * process the top object on the stack
			 */

			fts->root = fts->top = fts->bot = 0;

			/*
			 * initialize the top level
			 */

			if (f->fts_level == 0)
			{
				fts->parent->fts_number = f->fts_number;
				fts->parent->fts_pointer = f->fts_pointer;
				fts->parent->fts_statp = f->fts_statp;
				fts->parent->statb = *f->fts_statp;
				f->fts_parent = fts->parent;
				fts->diroot = 0;
				if (fts->cd == 0)
					pathcd(fts->home, NiL);
				else if (fts->cd < 0)
					fts->cd = 0;
				fts->pwd = f->fts_parent;
				fts->curdir = fts->cd ? 0 : f->fts_parent;
				*(fts->base = fts->path) = 0;
			}

			/*
			 * chdir to parent if asked for
			 */

			if (fts->cd < 0)
			{
				fts->cd = setdir(fts->home, fts->path);
				fts->pwd = f->fts_parent;
				fts->curdir = fts->cd ? 0 : f->fts_parent;
			}

			/*
			 * add object's name to the path
			 */

			if ((fts->baselen = f->fts_namelen) >= (fts->endbuf - fts->base) && resize(fts, fts->baselen))
				return 0;
			memcpy(fts->base, f->name, fts->baselen + 1);
			fts->name = fts->cd ? fts->path : fts->base;
			/*FALLTHROUGH*/

		case FTS_preorder:

			/*
			 * check for cycle and open dir
			 */

			if (f->fts_info == FTS_D)
			{
				if ((fts->diroot = search(f, fts->diroot, statcmp, 0)) != f || f->fts_level > 0 && (t = f) && statcmp(&t, &f->fts_parent) == 0)
				{
					f->fts_info = FTS_DC;
					f->fts_cycle = fts->diroot;
				}
				else if (!(fts->flags & FTS_TOP) && (!(fts->flags & FTS_XDEV) || f->statb.st_dev == f->fts_parent->statb.st_dev))
				{
					/*
					 * buffer is known to be large enough here!
					 */

					if (fts->base[fts->baselen - 1] != '/')
						memcpy(fts->base + fts->baselen, "/.", 3);
					if (!(fts->dir = opendir(fts->name)))
						f->fts_info = FTS_DNX;
					fts->base[fts->baselen] = 0;
					if (!fts->dir && !(fts->dir = opendir(fts->name)))
						f->fts_info = FTS_DNR;
				}
			}
			f->nd = f->fts_info & ~FTS_DNX;
			if (f->nd || !(fts->flags & FTS_NOPREORDER))
			{
				fts->current = f;
				fts->link = f->fts_link;
				f->fts_link = 0;
				f->fts_path = PATH(fts, fts->path, f->fts_level);
				f->fts_pathlen = (fts->base - f->fts_path) + fts->baselen;
				f->fts_accpath = ACCESS(fts, f);
				fts->state = FTS_preorder_return;
				goto note;
			}
			/*FALLTHROUGH*/

		case FTS_preorder_resume:

			/*
			 * prune
			 */

			if (!fts->dir || f->nd || f->status == FTS_SKIP)
			{
				if (fts->dir)
				{
					closedir(fts->dir);
					fts->dir = 0;
				}
				fts->state = FTS_popstack;
				continue;
			}

			/*
			 * FTS_D or FTS_DNX, about to read children
			 */

			if (fts->cd == 0)
			{
				if ((fts->cd = chdir(fts->name)) < 0)
					pathcd(fts->home, NiL);
				else if (fts->pwd != f)
				{
					f->pwd = fts->pwd;
					fts->pwd = f;
				}
				fts->curdir = fts->cd < 0 ? 0 : f;
			}
			fts->nostat = fts->children > 1 || f->fts_info == FTS_DNX;
			fts->cpname = fts->cd && !fts->nostat || !fts->children && !fts->comparf;
			fts->dotdot = 0;
			fts->endbase = fts->base + fts->baselen;
			if (fts->endbase[-1] != '/')
				*fts->endbase++ = '/';
			fts->current = f;
			/*FALLTHROUGH*/

		case FTS_readdir:

			while (d = readdir(fts->dir))
			{
				s = d->d_name;
				if (s[0] == '.')
				{
					if (s[1] == 0)
					{
						fts->current->nlink--;
						if (!(fts->flags & FTS_SEEDOT))
							continue;
						n = 1;
					}
					else if (s[1] == '.' && s[2] == 0)
					{
						fts->current->nlink--;
						if (fts->current->must == 1)
							fts->current->must = 0;
						if (!(fts->flags & FTS_SEEDOT))
							continue;
						n = 2;
					}
					else
						n = 0;
				}
				else
					n = 0;

				/*
				 * make a new entry
				 */

				i = D_NAMLEN(d);
				if (!(f = node(fts, fts->current, s, i)))
					return 0;
				TYPE(f, D_TYPE(d));

				/*
				 * check for space
				 */

				if (i >= fts->endbuf - fts->endbase)
				{
		   	   		if (resize(fts, i))
						return 0;
					fts->endbase = fts->base + fts->baselen;
					if (fts->endbase[-1] != '/')
						fts->endbase++;
				}
				if (fts->cpname)
				{
					memcpy(fts->endbase, s, i + 1);
					if (fts->cd)
						s = fts->path;
				}
				if (n)
				{
					/*
					 * don't recurse on . and ..
					 */

					if (n == 1)
						f->fts_statp = fts->current->fts_statp;
					else
					{
						if (f->fts_info != FTS_NS)
							fts->dotdot = f;
						if (fts->current->fts_parent->fts_level < 0)
						{
							f->fts_statp = &fts->current->fts_parent->statb;
							info(fts, f, s, f->fts_statp, 0);
						}
						else
							f->fts_statp = fts->current->fts_parent->fts_statp;
					}
					f->fts_info = FTS_DOT;
				}
				else if ((fts->nostat || SKIP(fts, f)) && (f->fts_info = FTS_NSOK) || info(fts, f, s, &f->statb, fts->flags))
					f->statb.st_ino = D_FILENO(d);
				if (fts->comparf)
					fts->root = search(f, fts->root, fts->comparf, 1);
				else if (fts->children || f->fts_info == FTS_D || f->fts_info == FTS_SL)
				{
					if (fts->top)
						fts->bot = fts->bot->fts_link = f;
					else
						fts->top = fts->bot = f;
				}
				else
				{
					/*
					 * terminal node
					 */

					f->fts_path = PATH(fts, fts->path, 1);
					f->fts_pathlen = fts->endbase - f->fts_path + f->fts_namelen;
					f->fts_accpath = ACCESS(fts, f);
					fts->previous = fts->current;
					fts->current = f;
					fts->state = FTS_terminal;
					goto note;
				}
			}

			/*
			 * done with the directory
			 */

			closedir(fts->dir);
			fts->dir = 0;
			if (fts->root)
				getlist(&fts->top, &fts->bot, fts->root);
			if (fts->children)
			{	
				/*
				 * try moving back to parent dir
				 */

				fts->base[fts->baselen] = 0;
				if (fts->cd <= 0)
				{
					f = fts->current->fts_parent;
					if (fts->cd < 0
					    || f != fts->curdir
					    || !fts->dotdot
					    || !SAME(f->fts_statp, fts->dotdot->fts_statp)
					    || fts->pwd && fts->pwd->symlink
					    || (fts->cd = chdir("..")) < 0
#ifdef verify
					    || stat(".", &sb) < 0
					    || !SAME(&sb, fts->dotdot->fts_statp)
#endif
					    )
						fts->cd = setpdir(fts->home, fts->path, fts->base);
					if (fts->pwd)
						fts->pwd = fts->pwd->pwd;
					fts->curdir = fts->cd ? 0 : f;
				}
				f = fts->current;
				fts->link = f->fts_link;
				f->fts_link = fts->top;
				f->fts_path = PATH(fts, fts->path, f->fts_level);
				f->fts_pathlen = (fts->base - f->fts_path) + f->fts_namelen;
				f->fts_accpath = ACCESS(fts, f);
				fts->state = FTS_children_return;
				goto note;
			}
			/*FALLTHROUGH*/

		case FTS_children_resume:

			fts->base[fts->baselen] = 0;
			if (fts->top)
			{
				fts->bot->fts_link = fts->todo;
				fts->todo = fts->top;
				fts->top = 0;
			}
			/*FALLTHROUGH*/

		case FTS_popstack:

			/*
			 * pop objects completely processed
			 */

			fts->nd = 0;
			f = fts->current;
			/*FALLTHROUGH*/

		case FTS_popstack_resume:

			while (fts->todo && f == fts->todo)
			{
				t = f->fts_parent;
				if ((f->fts_info & FTS_DP) == FTS_D)
				{
					/*
					 * delete from <dev,ino> tree
					 */

					if (f != fts->diroot)
						fts->diroot = search(f, fts->diroot, statcmp, 0);
					fts->diroot = deleteroot(fts->diroot);
					if (f == fts->curdir)
					{
						fts->nd++;
						fts->curdir = t;
					}

					/*
					 * perform post-order processing
					 */

					if (!(fts->flags & FTS_NOPOSTORDER) &&
					    f->status != FTS_SKIP &&
					    f->status != FTS_NOPOSTORDER)
					{
						/*
						 * move to parent dir
						 */

						if (fts->nd > 0)
							fts->cd = popdirs(fts);
						if (fts->cd < 0)
							fts->cd = setpdir(fts->home, fts->path, fts->base);
						fts->curdir = fts->cd ? 0 : t;
						f->fts_info = FTS_DP;
						f->fts_path = PATH(fts, fts->path, f->fts_level);
						f->fts_pathlen = (fts->base - f->fts_path) + f->fts_namelen;
						f->fts_accpath = ACCESS(fts, f);

						/*
						 * re-stat to update nlink/times
						 */

						stat(f->fts_accpath, f->fts_statp);
						fts->link = f->fts_link;
						f->fts_link = 0;
						fts->state = FTS_popstack_return;
						goto note;
					}
				}

				/*
				 * reset base
				 */

				if (fts->base > fts->path + t->fts_namelen)
					fts->base--;
				*fts->base = 0;
				fts->base -= t->fts_namelen;

				/*
				 * try again or delete from top of stack
				 */

				if (f->status == FTS_AGAIN)
				{
					f->fts_info = FTS_D;
					f->status = 0;
				}
				else
				{
					fts->todo = fts->todo->fts_link;
					drop(fts, f);
				}
				f = t;
			}

			/*
			 * reset current directory
			 */

			if (fts->nd > 0 && popdirs(fts) < 0)
			{
				pathcd(fts->home, NiL);
				fts->curdir = 0;
				fts->cd = -1;
			}
			if (fts->todo)
			{
				if (*fts->base)
					fts->base += f->fts_namelen;
				if (*(fts->base - 1) != '/')
					*fts->base++ = '/';
				*fts->base = 0;
				f = fts->todo;
				fts->state = FTS_todo;
				continue;
			}
			return 0;

		case FTS_children_return:

			f = fts->current;
			f->fts_link = fts->link;

			/*
			 * chdir down again
			 */

			i = f->fts_info != FTS_DNX;
			n = f->status == FTS_SKIP;
			if (!n && fts->cd == 0)
			{
				if ((fts->cd = chdir(fts->base)) < 0)
					pathcd(fts->home, NiL);
				else if (fts->pwd != f)
				{
					f->pwd = fts->pwd;
					fts->pwd = f;
				}
				fts->curdir = fts->cd ? 0 : f;
			}

			/*
			 * prune
			 */

			if (fts->base[fts->baselen - 1] != '/')
				fts->base[fts->baselen] = '/';
			for (fts->bot = 0, f = fts->top; f; )
				if (n || f->status == FTS_SKIP)
				{
					if (fts->bot)
						fts->bot->fts_link = f->fts_link;
					else
						fts->top = f->fts_link;
					drop(fts, f);
					f = fts->bot ? fts->bot->fts_link : fts->top;
				}
				else
				{
					if (fts->children > 1 && i)
					{
						if (f->status == FTS_STAT)
							info(fts, f, NiL, f->fts_statp, 0);
						else if (f->fts_info == FTS_NSOK && !SKIP(fts, f))
						{
							s = f->fts_name;
							if (fts->cd)
							{
								memcpy(fts->endbase, s, f->fts_namelen + 1);
								s = fts->path;
							}
							info(fts, f, s, f->fts_statp, fts->flags);
						}
					}
					fts->bot = f;
					f = f->fts_link;
				}
			fts->children = 0;
			fts->state = FTS_children_resume;
			continue;

		case FTS_popstack_return:

			f = fts->todo;
			f->fts_link = fts->link;
			f->fts_info = f->status == FTS_AGAIN ? FTS_DP : 0;
			fts->state = FTS_popstack_resume;
			continue;

		case FTS_preorder_return:

			f = fts->current;
			f->fts_link = fts->link;

			/*
			 * follow symlink if asked to
			 */

			if (f->status == FTS_FOLLOW)
			{
				f->status = 0;
				if (f->fts_info == FTS_SL || ISTYPE(f, DT_LNK) || f->fts_info == FTS_NSOK)
				{
					info(fts, f, f->fts_accpath, f->fts_statp, 0);
					if (f->fts_info != FTS_SL)
					{
						fts->state = FTS_preorder;
						continue;
					}
				}
			}

			/*
			 * about to prune this f and already at home
			 */

			if (fts->cd == 0 && f->fts_level == 0 && f->nd)
				fts->cd = -1;
			fts->state = FTS_preorder_resume;
			continue;

		case FTS_terminal:

			f = fts->current;
			if (f->status == FTS_FOLLOW)
			{
				f->status = 0;
				if (f->fts_info == FTS_SL || ISTYPE(f, DT_LNK) || f->fts_info == FTS_NSOK)
				{
					info(fts, f, f->fts_accpath, f->fts_statp, 0);
					if (f->symlink && f->fts_info != FTS_SL)
					{
						if (!(f->fts_link = fts->top))
							fts->bot = f;
						fts->top = f;
						fts->current = fts->previous;
						fts->state = FTS_readdir;
						continue;
					}
				}
			}
			f = f->fts_parent;
			drop(fts, fts->current);
			fts->current = f;
			fts->state = FTS_readdir;
			continue;

		case FTS_error:

			return 0;

		default:

			fts->fts_errno = EINVAL;
			fts->state = FTS_error;
			return 0;

		}
 note:
#if __OBSOLETE__ < 20140101
	f->_fts_pathlen = (unsigned short)f->fts_pathlen;
#endif
	for (p = notify; p; p = p->next)
		if ((n = (*p->notifyf)(fts, f, p->context)) > 0)
			break;
		else if (n < 0)
		{
			fts->fts_errno = EINVAL;
			fts->state = FTS_error;
			return 0;
		}
	return f;
}

/*
 * set stream or entry flags
 */

int
fts_set(register FTS* fts, register FTSENT* f, int status)
{
	if (fts || !f || f->fts->current != f)
		return -1;
	switch (status)
	{
	case FTS_AGAIN:
		break;
	case FTS_FOLLOW:
		if (!(f->fts_info & FTS_SL))
			return -1;
		break;
	case FTS_NOPOSTORDER:
		break;
	case FTS_SKIP:
		if ((f->fts_info & (FTS_D|FTS_P)) != FTS_D)
			return -1;
		break;
	default:
		return -1;
	}
	f->status = status;
	return 0;
}

/*
 * return the list of child entries
 */

FTSENT*
fts_children(register FTS* fts, int flags)
{
	register FTSENT*	f;

	switch (fts->state)
	{

	case 0:

		if (fts->comparf)
			order(fts);
		fts->state = FTS_top_return;
		return fts->todo;

	case FTS_preorder_return:

		fts->children = ((flags | fts->flags) & FTS_NOSTAT) ? 2 : 1;
		if (f = fts_read(fts))
			f = f->fts_link;
		return f;

	}
	return 0;
}

/*
 * return default (FTS_LOGICAL|FTS_META|FTS_PHYSICAL|FTS_SEEDOTDIR) flags
 * conditioned by astconf()
 */

int
fts_flags(void)
{
	register char*	s;
	
	s = astconf("PATH_RESOLVE", NiL, NiL);
	if (streq(s, "logical"))
		return FTS_LOGICAL;
	if (streq(s, "physical"))
		return FTS_PHYSICAL|FTS_SEEDOTDIR;
	return FTS_META|FTS_PHYSICAL|FTS_SEEDOTDIR;
}

/*
 * return 1 if ent is mounted on a local filesystem
 */

int
fts_local(FTSENT* ent)
{
#ifdef ST_LOCAL
	struct statvfs	fs;

	return statvfs(ent->fts_path, &fs) || (fs.f_flag & ST_LOCAL);
#else
	return !strgrpmatch(fmtfs(ent->fts_statp), "([an]fs|samb)", NiL, 0, STR_LEFT|STR_ICASE);
#endif
}

/*
 * close an open fts stream
 */

int
fts_close(register FTS* fts)
{
	register FTSENT*	f;
	register FTSENT*	x;

	if (fts->dir)
		closedir(fts->dir);
	if (fts->cd == 0)
		pathcd(fts->home, NiL);
	free(fts->home);
	if (fts->state == FTS_children_return)
		fts->current->fts_link = fts->link;
	if (fts->top)
	{
		fts->bot->fts_link = fts->todo;
		fts->todo = fts->top;
	}
	for (f = fts->todo; f; f = x)
	{
		x = f->fts_link;
		free(f);
	}
	for (f = fts->free; f; f = x)
	{
		x = f->fts_link;
		free(f);
	}
	free(fts);
	return 0;
}

/*
 * register function to be called for each fts_read() entry
 * context==0 => unregister notifyf
 */

int
fts_notify(Notify_f notifyf, void* context)
{
	register Notify_t*	np;
	register Notify_t*	pp;

	if (context)
	{
		if (!(np = newof(0, Notify_t, 1, 0)))
			return -1;
		np->notifyf = notifyf;
		np->context = context;
		np->next = notify;
		notify = np;
	}
	else
	{
		for (np = notify, pp = 0; np; pp = np, np = np->next)
			if (np->notifyf == notifyf)
			{
				if (pp)
					pp->next = np->next;
				else
					notify = np->next;
				free(np);
				return 0;
			}
		return -1;
	}
	return 0;
}
