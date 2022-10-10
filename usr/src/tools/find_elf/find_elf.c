/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Joyent, Inc.
 * Copyright 2022 Jason King
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/avl.h>
#include <sys/fcntl.h>
#include <sys/sysmacros.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libcustr.h>
#include <libelf.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static inline bool
is_same(const struct stat *s1, const struct stat *s2)
{
	if ((s1->st_ino == s2->st_ino) && (s1->st_dev == s2->st_dev))
		return (true);
	return (false);
}

typedef enum dir_flags {
	DF_NONE =	0,
	DF_IS_SELF =	1 << 0,
	DF_IS_SYMLINK =	1 << 2,
} dir_flags_t;

typedef struct path {
	custr_t	*p_name;
	size_t	p_pfxidx;
} path_t;

typedef struct name {
	char	*n_name;
	bool	n_is_symlink;
} name_t;

typedef struct names {
	name_t	*ns_names;
	uint_t	ns_num;
	uint_t	ns_alloc;
} names_t;

typedef struct elfinfo {
	int		ei_class;
	uint16_t	ei_type;
	bool		ei_hasverdef;
} elfinfo_t;

typedef struct obj {
	avl_node_t	obj_avlid;
	avl_node_t	obj_avlname;
	dev_t		obj_dev;
	ino_t		obj_inode;
	names_t		obj_names;
	elfinfo_t	obj_elfinfo;
} obj_t;

static void path_init(path_t *, const char *, bool);
static size_t path_append(path_t *, const char *);
static const char *path_name(const path_t *);
static const char *path_fullpath(const path_t *);
static void path_pop(path_t *, size_t);

static bool maybe_obj(const char *, mode_t);
static bool get_elfinfo(const path_t *, int, elfinfo_t *);
static void add_name(obj_t *, const path_t *, bool);
static int cmp_id(const void *, const void *);
static int cmp_objname(const void *, const void *);
static int cmp_names(const void *, const void *);

static void process_dir(path_t *, int, const struct stat *, dir_flags_t);
static void process_file(path_t *, int, const struct stat *, bool);
static void process_arg(char *);

static void sort_names(void *, void *);
static void print_entry(void *, void *);

static void foreach_avl(avl_tree_t *, void (*)(void *, void *), void *);

static void nomem(void);
static char *xstrdup(const char *);
static void *xcalloc(size_t, size_t);

static avl_tree_t avl_byid;
static avl_tree_t avl_byname;

static const char *special_paths[] = {
	"usr/bin/alias",
	"usr/lib/isaexec",
};

static int rootfd = -1;

/* By default, we process aliases */
static bool do_alias = true;

/* By default, we treat certain well known names (e.g. isaexec) as special */
static bool do_special = true;

/* fast_mode, relpath, and so_only are all false by default */
static bool fast_mode;
static bool relpath;
static bool so_only;

static void __NORETURN
usage(const char *name)
{
	(void) fprintf(stderr,
	    "Usage: %s [-afnrs] file | dir\n"
	    "\t[-a]\texpand symlink aliases\n"
	    "\t[-f]\tuse file name at mode to speed search\n"
	    "\t[-h]\tshow this help\n"
	    "\t[-n]\tdon\'t treat well known paths as special in sorting\n"
	    "\t[-r]\treport relative paths\n"
	    "\t[-s]\tonly remote shareable (ET_DYN) objects\n", name);
	exit(EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	int c;

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EXIT_FAILURE, "elf library is out of date");

	while ((c = getopt(argc, argv, "ahfnrs")) != -1) {
		switch (c) {
		case 'a':
			do_alias = false;
			break;
		case 'f':
			fast_mode = true;
			break;
		case 'n':
			do_special = false;
			break;
		case 'r':
			relpath = true;
			break;
		case 's':
			so_only = true;
			break;
		case 'h':
			usage(argv[0]);
		case '?':
			(void) fprintf(stderr, "Unknown option -%c\n", optopt);
			usage(argv[0]);
		}
	}

	if (optind == argc) {
		(void) fprintf(stderr, "Missing file or dir parameter\n");
		usage(argv[0]);
	}

	if (argv[optind][0] == '\0')
		errx(EXIT_FAILURE, "Invalid file or dir value");

	avl_create(&avl_byid, cmp_id, sizeof (obj_t),
	    offsetof(obj_t, obj_avlid));
	avl_create(&avl_byname, cmp_objname, sizeof (obj_t),
	    offsetof(obj_t, obj_avlname));

	process_arg(argv[optind]);
	foreach_avl(&avl_byid, sort_names, &avl_byname);
	foreach_avl(&avl_byname, print_entry, NULL);

	return (EXIT_SUCCESS);
}

static void
process_arg(char *arg)
{
	path_t path;
	struct stat sb;
	int fd;

	if ((fd = open(arg, O_RDONLY)) == -1) {
		err(EXIT_FAILURE, "could not open %s", arg);
	}

	if (fstat(fd, &sb) < 0) {
		err(EXIT_FAILURE, "failed to stat %s", arg);
	}

	if (S_ISDIR(sb.st_mode)) {
		path_init(&path, arg, relpath);
		if (relpath) {
			(void) printf("PREFIX %s\n", arg);
		}

		rootfd = fd;
		/* process_dir() will close fd */
		process_dir(&path, fd, &sb, DF_NONE);
		return;
	}

	char *argcopy = xstrdup(arg);
	char *dir = dirname(argcopy);

	if (!S_ISREG(sb.st_mode)) {
		err(EXIT_FAILURE, "not a file or directory: %s", arg);
	}

#ifndef O_DIRECTORY
	struct stat tsb;
	if (stat(dir, &tsb) == -1) {
		err(EXIT_FAILURE, "failed to stat %s", dir);
	}
	if (!S_ISDIR(tsb.st_mode)) {
		errx(EXIT_FAILURE, "not a directory: %s", dir);
	}
	rootfd = open(dir, O_RDONLY);
#else
	rootfd = open(dir, O_RDONLY|O_DIRECTORY);
#endif
	if (rootfd < 0) {
		err(EXIT_FAILURE, "%s", dir);
	}

	path_init(&path, dir, relpath);
	if (relpath) {
		(void) printf("PREFIX %s\n", dir);
	}
	free(argcopy);

	process_file(&path, fd, &sb, DF_NONE);
}

/*
 * Processing a directory has some subtleties. When we encounter a
 * subdirectory that's a symlink, we want any files we encounter when
 * we traverse it to be treated as aliases. We may also have a symlink that's
 * a link back to ourself (e.g. 32 -> .). In this special case, we still want
 * to reprocess the directory to generate alias names, but we use the
 * DFLAG_SELF flag to avoid recursing forever.
 *
 * A limitation of this approach is that we cannot handle a loop over multiple
 * levels (e.g. foo -> ../..). Nothing currently in illumos-gate creates any
 * such symlinks in the proto area, so we've opted to avoid complicating
 * processing further to handle scenarios that aren't realistically expected
 * to occur.
 *
 * Note that dirfd is always closed upon return from process_dir().
 */
static void
process_dir(path_t *p, int dirfd, const struct stat *dirsb, dir_flags_t dflags)
{
	DIR *d;
	struct dirent *de;

	d = fdopendir(dirfd);
	if (d == NULL) {
		warn("opendir(%s)", path_fullpath(p));
		VERIFY0(close(dirfd));
		return;
	}

	while ((de = readdir(d)) != NULL) {
		struct stat sb;
		int fd;
		bool is_link = false;
		size_t plen;

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0) {
			continue;
		}

		plen = path_append(p, de->d_name);

		if (fstatat(rootfd, path_name(p), &sb,
		    AT_SYMLINK_NOFOLLOW) < 0) {
			warn("%s", path_fullpath(p));
			path_pop(p, plen);
			continue;
		}

		fd = openat(dirfd, de->d_name, O_RDONLY);
		if (fd < 0) {
			/*
			 * Symlinks in the proto area may point to a path
			 * that's not present (e.g. /dev/stdin -> fd/0).
			 * Silently skip such entries.
			 */
			if (errno != ENOENT || !S_ISLNK(sb.st_mode)) {
				warn("%s", path_fullpath(p));
			}
			path_pop(p, plen);
			continue;
		}

		if (S_ISLNK(sb.st_mode)) {
			is_link = true;

			if (fstat(fd, &sb) < 0) {
				warn("stat %s", path_fullpath(p));
				path_pop(p, plen);
				continue;
			}
		}

		if (S_ISDIR(sb.st_mode)) {
			if ((dflags & DF_IS_SELF) != 0) {
				VERIFY0(close(fd));
				path_pop(p, plen);
				continue;
			}

			dir_flags_t newflags = dflags;

			/* The recursive process_dir() call closes fd */
			if (is_link)
				newflags |= DF_IS_SYMLINK;
			if (is_same(&sb, dirsb))
				newflags |= DF_IS_SELF;
			process_dir(p, fd, &sb, newflags);
		} else if (S_ISREG(sb.st_mode)) {
			if (!maybe_obj(de->d_name, sb.st_mode)) {
				VERIFY0(close(fd));
				path_pop(p, plen);
				continue;
			}

			if ((dflags & (DF_IS_SELF | DF_IS_SYMLINK)) != 0)
				is_link = true;

			/* process_file() closes fd */
			process_file(p, fd, &sb, is_link);
		}

		path_pop(p, plen);
	}

	/* Closes dirfd */
	VERIFY0(closedir(d));
}

/* Note that fd is always closed upon return */
static void
process_file(path_t *p, int fd, const struct stat *sb, bool is_link)
{
	avl_index_t where = { 0 };
	obj_t templ = {
		.obj_dev = sb->st_dev,
		.obj_inode = sb->st_ino,
	};
	obj_t *obj = avl_find(&avl_byid, &templ, &where);
	elfinfo_t elfinfo = { 0 };

	if (obj != NULL)
		goto done;

	if (!get_elfinfo(p, fd, &elfinfo)) {
		VERIFY0(close(fd));
		return;
	}

	obj = xcalloc(1, sizeof (*obj));
	obj->obj_dev = sb->st_dev;
	obj->obj_inode = sb->st_ino;
	obj->obj_elfinfo = elfinfo;
	avl_add(&avl_byid, obj);

done:
	add_name(obj, p, is_link);
	VERIFY0(close(fd));
}

static void
print_entry(void *a, void *arg __unused)
{
	obj_t *obj = a;
	const char *objname = obj->obj_names.ns_names[0].n_name;
	const char *bits = "";
	const char *type = "";
	const char *verdef = obj->obj_elfinfo.ei_hasverdef ?
	    "VERDEF" : "NOVERDEF";

	switch (obj->obj_elfinfo.ei_class) {
	case ELFCLASS32:
		bits = "32";
		break;
	case ELFCLASS64:
		bits = "64";
		break;
	default:
		errx(EXIT_FAILURE, "unknown elfclass value %x for %s",
		    obj->obj_elfinfo.ei_class, objname);
	}

	switch (obj->obj_elfinfo.ei_type) {
	case ET_REL:
		type = "REL";
		break;
	case ET_DYN:
		type = "DYN";
		break;
	case ET_EXEC:
		type = "EXEC";
		break;
	default:
		errx(EXIT_FAILURE, "unexpected elf type %x for %s",
		    obj->obj_elfinfo.ei_type, objname);
	}

	names_t *names = &obj->obj_names;

	VERIFY3U(names->ns_num, >, 0);
	VERIFY(!names->ns_names[0].n_is_symlink);

	(void) printf("OBJECT %2s %-4s %-8s %s\n", bits, type, verdef,
	    objname);

	for (uint_t i = 1; i < names->ns_num; i++) {
		if (do_alias) {
			(void) printf("%-23s %s\t%s\n",
			    "ALIAS", objname, names->ns_names[i].n_name);
		} else {
			(void) printf("OBJECT %2s %-4s %-8s %s\n", bits, type,
			    verdef, names->ns_names[i].n_name);
		}
	}
}

/*
 * Returns true and eip populated if name was an elf object, otherwise
 * returns false.
 */
static bool
get_elfinfo(const path_t *p, int fd, elfinfo_t *eip)
{
	Elf *elf = NULL;
	Elf_Scn *scn = NULL;
	GElf_Ehdr ehdr = { 0 };
	int eval;

	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		goto fail_noend;

	if ((eip->ei_class = gelf_getclass(elf)) == ELFCLASSNONE) {
		VERIFY0(elf_end(elf));
		return (false);
	}

	if (gelf_getehdr(elf, &ehdr) == NULL)
		goto fail;

	eip->ei_type = ehdr.e_type;
	eip->ei_hasverdef = false;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		Elf_Data *data = NULL;
		GElf_Shdr shdr = { 0 };

		if (gelf_getshdr(scn, &shdr) == NULL)
			goto fail;

		if (shdr.sh_type != SHT_DYNAMIC)
			continue;

		if ((data = elf_getdata(scn, NULL)) == NULL)
			continue;

		size_t nent = shdr.sh_size / shdr.sh_entsize;

		for (size_t i = 0; i < nent; i++) {
			GElf_Dyn dyn = { 0 };

			if (gelf_getdyn(data, i, &dyn) == NULL) {
				goto fail;
			}

			if (dyn.d_tag == DT_VERDEF) {
				eip->ei_hasverdef = true;
				break;
			}
		}
	}

	VERIFY0(elf_end(elf));
	return (true);

fail:
	VERIFY0(elf_end(elf));

fail_noend:
	eval = elf_errno();

	warnx("%s: %s", path_fullpath(p), elf_errmsg(eval));
	return (false);
}

static bool
is_special(const char *name)
{
	for (uint_t i = 0; i < ARRAY_SIZE(special_paths); i++) {
		if (strcmp(special_paths[i], name) == 0)
			return (true);
	}
	return (false);
}

static void
sort_names(void *a, void *b)
{
	obj_t *obj = a;
	avl_tree_t *name_avl = b;
	names_t *names = &obj->obj_names;

	/* We should always have at least one name */
	VERIFY3U(names->ns_num, >, 0);

	/* If there is only one, they get the prize and we're done */
	if (names->ns_num == 1)
		return;

	name_t *first = NULL;

	/*
	 * Find the first (in sorted order) pathname for this object
	 * that isn't a symlink.
	 */
	for (uint_t i = 0; i < names->ns_num; i++) {
		name_t *n = &names->ns_names[i];

		if (n->n_is_symlink)
			continue;

		if (first == NULL) {
			first = n;
			continue;
		}

		/*
		 * If we're treating isaexec as special, we always
		 * want it to be the first entry. Otherwise, pick
		 * the 'lowest' sorted pathname.
		 */
		if (do_special) {
			if (is_special(n->n_name)) {
				first = n;
				break;
			}

			if (strcmp(n->n_name, first->n_name) < 0)
				first = n;
		}
	}

	/*
	 * If the first pathname (in sorted order) isn't the first
	 * name entry, we swap it into first place (while also updating
	 * the names AVL tree).
	 */
	if (first != NULL && first != &names->ns_names[0]) {
		name_t tmp = names->ns_names[0];

		avl_remove(name_avl, obj);
		(void) memcpy(&names->ns_names[0], first, sizeof (name_t));
		(void) memcpy(first, &tmp, sizeof (name_t));
		avl_add(name_avl, obj);
	}

	/*
	 * The remaining names (symlinks or not) are sorted by
	 * their pathname.
	 */
	qsort(&names->ns_names[1], names->ns_num - 1, sizeof (name_t),
	    cmp_names);
}

/*
 * We grow the names array by NAME_CHUNK entries every time we need to
 * extend it.
 */
#define	NAME_CHUNK	4

static name_t *
name_new(names_t *names)
{
	if (names->ns_num < names->ns_alloc)
		return (&names->ns_names[names->ns_num++]);

	name_t *newn = NULL;
	uint_t newamt = names->ns_alloc + NAME_CHUNK;

	/*
	 * Since we may be building on a machine that doesn't
	 * have reallocarray or the like, we avoid their use here.
	 * If we ever officially designate an illumos-gate build
	 * as the minimum required to build master that contains
	 * reallocarray and such, we can replace most of this logic
	 * with it.
	 *
	 * Also use xcalloc so we get the unused entries zeroed already.
	 * Not strictly necessary, but useful for debugging.
	 */
	newn = xcalloc(newamt, sizeof (name_t));

	/* Move over existing entries */
	(void) memcpy(newn, names->ns_names, names->ns_num * sizeof (name_t));

	free(names->ns_names);

	names->ns_names = newn;
	names->ns_alloc = newamt;
	return (&names->ns_names[names->ns_num++]);
}

static void
add_name(obj_t *obj, const path_t *p, bool is_symlink)
{
	names_t *ns = &obj->obj_names;
	const char *srcname = path_name(p);

	/* We should never have duplicates */
	for (size_t i = 0; i < ns->ns_num; i++)
		VERIFY3S(strcmp(ns->ns_names[i].n_name, srcname), !=, 0);

	name_t *n = name_new(ns);

	n->n_name = xstrdup(srcname);
	n->n_is_symlink = is_symlink;

	if (is_symlink)
		return;

	/*
	 * If the name was not a symlink, first determine if there are
	 * existing (hard) links to this name already, and if so, which entry
	 * is the first one. Typically this will be the name we just added
	 * unless the file does have multiple hard links (e.g. isaexec).
	 */
	uint_t nhlink = 0;
	uint_t firsthlink = UINT_MAX;

	for (uint_t i = 0; i < ns->ns_num; i++) {
		if (ns->ns_names[i].n_is_symlink)
			continue;
		if (nhlink == 0)
			firsthlink = i;
		nhlink++;
	}

	if (nhlink > 1)
		return;

	/*
	 * Put the first non-symlink name as the very first
	 * entry.
	 */
	VERIFY3U(firsthlink, !=, UINT_MAX);

	if (firsthlink != 0) {
		name_t tmp = {
			.n_name = ns->ns_names[0].n_name,
			.n_is_symlink = ns->ns_names[0].n_is_symlink,
		};

		(void) memcpy(&ns->ns_names[0], &ns->ns_names[firsthlink],
		    sizeof (name_t));
		(void) memcpy(&ns->ns_names[firsthlink], &tmp, sizeof (name_t));
	}

	avl_add(&avl_byname, obj);
}

/*
 * This is an arbitrary initial value -- basically we can nest 16 directories
 * deep before having to grow p->p_idx (which seems like a nice power of 2).
 */
#define	PATH_INIT	16

static void
path_init(path_t *p, const char *name, bool relpath)
{
	(void) memset(p, '\0', sizeof (*p));

	if (custr_alloc(&p->p_name) < 0) {
		nomem();
	}

	if (name != NULL && custr_append(p->p_name, name) < 0)
		nomem();

	size_t len = custr_len(p->p_name);

	/* Trim off any trailing /'s, but don't trim '/' to an empty path */
	while (len > 1 && custr_cstr(p->p_name)[len - 1] == '/') {
		VERIFY0(custr_rtrunc(p->p_name, 0));
		len--;
	}

	p->p_pfxidx = relpath ? len + 1 : 0;
}

static size_t
path_append(path_t *p, const char *name)
{
	size_t clen = custr_len(p->p_name);

	if (clen > 0)
		VERIFY0(custr_appendc(p->p_name, '/'));
	VERIFY0(custr_append(p->p_name, name));

	return (clen);
}

static const char *
path_name(const path_t *p)
{
	return (custr_cstr(p->p_name) + p->p_pfxidx);
}

static const char *
path_fullpath(const path_t *p)
{
	return (custr_cstr(p->p_name));
}

static void
path_pop(path_t *p, size_t idx)
{
	VERIFY0(custr_trunc(p->p_name, idx));
}

static int
cmp_id(const void *a, const void *b)
{
	const obj_t *l = a;
	const obj_t *r = b;

	if (l->obj_dev < r->obj_dev)
		return (-1);
	if (l->obj_dev > r->obj_dev)
		return (1);
	if (l->obj_inode < r->obj_inode)
		return (-1);
	if (l->obj_inode > r->obj_inode)
		return (1);
	return (0);
}

static int
cmp_objname(const void *a, const void *b)
{
	const obj_t *l = a;
	const obj_t *r = b;
	const name_t *ln = &l->obj_names.ns_names[0];
	const name_t *rn = &r->obj_names.ns_names[0];

	return (cmp_names(ln, rn));
}

static int
cmp_names(const void *a, const void *b)
{
	const name_t *l = a;
	const name_t *r = b;
	int cmp = strcmp(l->n_name, r->n_name);

	if (cmp < 0)
		return (-1);
	if (cmp > 0)
		return (1);
	return (0);
}

/*
 * Use the filename and permission bits to determine if this file could
 * possibly be an executable.
 */
static bool
maybe_obj(const char *name, mode_t mode)
{
	/* If not in fast mode, check everything, so always return true */
	if (!fast_mode)
		return (true);

	size_t len = strlen(name);

	/* If the file name ends in .so, we check */
	if (len >= 3 && strcmp(&name[len - 4], ".so") == 0) {
		return (true);
	}

	/* If the file name contains '.so', we check */
	if (len >= 4 && strstr(name, ".so.") != NULL) {
		return (true);
	}

	/* If the above checks fail, we assume it's not a shared library */
	if (so_only)
		return (false);

	/*
	 * The original perl script used a -x test which only looked at
	 * file permissions. This may return slightly different results
	 * than using access(2) or faccessat(2).
	 */
	if ((mode & (S_IXUSR|S_IXGRP|S_IXOTH)) == 0)
		return (false);

	return (true);
}

static void
foreach_avl(avl_tree_t *avl, void (*cb)(void *, void *), void *arg)
{
	void *obj;

	for (obj = avl_first(avl); obj != NULL; obj = AVL_NEXT(avl, obj))
		cb(obj, arg);
}

static char *
xstrdup(const char *s)
{
	char *news = strdup(s);

	if (news == NULL) {
		nomem();
	}
	return (news);
}

static void *
xcalloc(size_t nelem, size_t elsize)
{
	void *p = calloc(nelem, elsize);

	if (p == NULL) {
		nomem();
	}

	return (p);
}

#define	NOMEM_MSG "out of memory\n"
static void __NORETURN
nomem(void)
{
	/* Try to get the error out before aborting */
	(void) write(STDERR_FILENO, NOMEM_MSG, sizeof (NOMEM_MSG));
	abort();
}
