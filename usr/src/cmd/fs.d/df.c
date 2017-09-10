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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2016 Jason King
 */

#include <dlfcn.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <stdlib.h>
#include <ftw.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <sys/vfstab.h>
#include <sys/wait.h>
#include <sys/mkdev.h>
#include <sys/int_limits.h>
#include <sys/zone.h>
#include <sys/debug.h>
#include <libzfs.h>
#include <libcmdutils.h>

#include "fslib.h"

extern char *default_fstype(char *);

/*
 * General notice:
 * String pointers in this code may point to statically allocated memory
 * or dynamically allocated memory. Furthermore, a dynamically allocated
 * string may be pointed to by more than one pointer. This does not pose
 * a problem because malloc'ed memory is never free'd (so we don't need
 * to remember which pointers point to malloc'ed memory).
 */

/*
 * TRANSLATION_NOTE
 * Only strings passed as arguments to the TRANSLATE macro need to
 * be translated.
 */

#ifndef MNTTYPE_LOFS
#define	MNTTYPE_LOFS		"lofs"
#endif

#define	EQ(s1, s2)		(strcmp(s1, s2) == 0)
#define	NEW(type)		xmalloc(sizeof (type))
#define	CLEAR(var)		(void) memset(&(var), 0, sizeof (var))
#define	MAX(a, b)		((a) > (b) ? (a) : (b))
#define	MAX3(a, b, c)		MAX(a, MAX(b, c))
#define	TRANSLATE(s)		new_string(gettext(s))

#define	MAX_OPTIONS		36
#define	N_FSTYPES		20
#define	MOUNT_TABLE_ENTRIES	40	/* initial allocation */
#define	MSGBUF_SIZE		1024
#define	LINEBUF_SIZE		256	/* either input or output lines */

#define	BLOCK_SIZE		512	/* when reporting in terms of blocks */

#define	DEVNM_CMD		"devnm"
#define	FS_LIBPATH		"/usr/lib/fs/"
#define	MOUNT_TAB		"/etc/mnttab"
#define	VFS_TAB			"/etc/vfstab"
#define	REMOTE_FS		"/etc/dfs/fstypes"

#define	NUL			'\0'
#define	FALSE			0
#define	TRUE			1

/*
 * Formatting constants
 */
#define	IBCS2_FILESYSTEM_WIDTH	15	/* Truncate to match ISC/SCO */
#define	IBCS2_MOUNT_POINT_WIDTH	10	/* Truncate to match ISC/SCO */
#define	FILESYSTEM_WIDTH	20
#define	MOUNT_POINT_WIDTH	19
#define	SPECIAL_DEVICE_WIDTH	18
#define	FSTYPE_WIDTH		8
#define	BLOCK_WIDTH		8
#define	NFILES_WIDTH		8
#define	KBYTE_WIDTH		11
#define	AVAILABLE_WIDTH		10
#define	SCALED_WIDTH		6
#define	CAPACITY_WIDTH		9
#define	BSIZE_WIDTH		6
#define	FRAGSIZE_WIDTH		7
#define	FSID_WIDTH		7
#define	FLAG_WIDTH		8
#define	NAMELEN_WIDTH		7
#define	MNT_SPEC_WIDTH		MOUNT_POINT_WIDTH + SPECIAL_DEVICE_WIDTH + 2

/*
 * Flags for the errmsg() function
 */
#define	ERR_NOFLAGS		0x0
#define	ERR_NONAME		0x1	/* don't include the program name */
					/* as a prefix */
#define	ERR_FATAL		0x2	/* call exit after printing the */
					/* message */
#define	ERR_PERROR		0x4	/* append an errno explanation to */
					/* the message */
#define	ERR_USAGE		0x8	/* print the usage line after the */
					/* message */

#define	NUMBER_WIDTH		40
CTASSERT(NUMBER_WIDTH >= NN_NUMBUF_SZ);

/*
 * A numbuf_t is used when converting a number to a string representation
 */
typedef char numbuf_t[ NUMBER_WIDTH ];

/*
 * We use bool_int instead of int to make clear which variables are
 * supposed to be boolean
 */
typedef int bool_int;

struct mtab_entry {
	bool_int	mte_dev_is_valid;
	dev_t		mte_dev;
	bool_int	mte_ignore;	/* the "ignore" option was set */
	struct extmnttab	*mte_mount;
};


struct df_request {
	bool_int		dfr_valid;
	char			*dfr_cmd_arg;	/* what the user specified */
	struct mtab_entry	*dfr_mte;
	char			*dfr_fstype;
	int			dfr_index;	/* to make qsort stable	*/
};

#define	DFR_MOUNT_POINT(dfrp)	(dfrp)->dfr_mte->mte_mount->mnt_mountp
#define	DFR_SPECIAL(dfrp)	(dfrp)->dfr_mte->mte_mount->mnt_special
#define	DFR_FSTYPE(dfrp)	(dfrp)->dfr_mte->mte_mount->mnt_fstype
#define	DFR_ISMOUNTEDFS(dfrp)	((dfrp)->dfr_mte != NULL)

#define	DFRP(p)			((struct df_request *)(p))

typedef void (*output_func)(struct df_request *, struct statvfs64 *);

struct df_output {
	output_func	dfo_func;	/* function that will do the output */
	int		dfo_flags;
};

/*
 * Output flags
 */
#define	DFO_NOFLAGS	0x0
#define	DFO_HEADER	0x1		/* output preceded by header */
#define	DFO_STATVFS	0x2		/* must do a statvfs64(2) */


static char	*program_name;
static char	df_options[MAX_OPTIONS] = "-";
static size_t	df_options_len = 1;
static char	*o_option_arg;			/* arg to the -o option */
static char	*FSType;
static char	*remote_fstypes[N_FSTYPES+1];	/* allocate an extra one */
						/* to use as a terminator */

/*
 * The following three variables support an in-memory copy of the mount table
 * to speedup searches.
 */
static struct mtab_entry	*mount_table;	/* array of mtab_entry's */
static size_t			mount_table_entries;
static size_t			mount_table_allocated_entries;

static bool_int		F_option;
static bool_int		V_option;
static bool_int		P_option;	/* Added for XCU4 compliance */
static bool_int		Z_option;
static bool_int		v_option;
static bool_int		a_option;
static bool_int		b_option;
static bool_int		e_option;
static bool_int		g_option;
static bool_int		h_option;
static bool_int		k_option;
static bool_int		l_option;
static bool_int		m_option;
static bool_int		n_option;
static bool_int		t_option;
static bool_int		o_option;

static bool_int		tty_output;
static bool_int		use_scaling;

static void usage(void);
static void do_devnm(int, char **);
static void do_df(int, char **)	__NORETURN;
static void parse_options(int, char **);
static char *basename(char *);

static libzfs_handle_t *(*_libzfs_init)(void);
static zfs_handle_t *(*_zfs_open)(libzfs_handle_t *, const char *, int);
static void (*_zfs_close)(zfs_handle_t *);
static uint64_t (*_zfs_prop_get_int)(zfs_handle_t *, zfs_prop_t);
static libzfs_handle_t *g_zfs;

/*
 * Dynamically check for libzfs, in case the user hasn't installed the SUNWzfs
 * packages.  A basic utility such as df shouldn't depend on optional
 * filesystems.
 */
static boolean_t
load_libzfs(void)
{
	void *hdl;

	if (_libzfs_init != NULL)
		return (g_zfs != NULL);

	if ((hdl = dlopen("libzfs.so", RTLD_LAZY)) != NULL) {
		_libzfs_init = (libzfs_handle_t *(*)(void))dlsym(hdl,
		    "libzfs_init");
		_zfs_open = (zfs_handle_t *(*)())dlsym(hdl, "zfs_open");
		_zfs_close = (void (*)())dlsym(hdl, "zfs_close");
		_zfs_prop_get_int = (uint64_t (*)())
		    dlsym(hdl, "zfs_prop_get_int");

		if (_libzfs_init != NULL) {
			assert(_zfs_open != NULL);
			assert(_zfs_close != NULL);
			assert(_zfs_prop_get_int != NULL);

			g_zfs = _libzfs_init();
		}
	}

	return (g_zfs != NULL);
}

int
main(int argc, char *argv[])
{
	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	program_name = basename(argv[0]);

	if (EQ(program_name, DEVNM_CMD))
		do_devnm(argc, argv);

	parse_options(argc, argv);

	/*
	 * The k_option implies SunOS 4.x compatibility: when the special
	 * device name is too long the line will be split except when the
	 * output has been redirected.
	 * This is also valid for the -h option.
	 */

	if (use_scaling || k_option || P_option || v_option)
		tty_output = isatty(1);

	do_df(argc - optind, &argv[optind]);
	/* NOTREACHED */
}


/*
 * Prints an error message to stderr.
 */
/* VARARGS2 */
static void
errmsg(int flags, char *fmt, ...)
{
	char buf[MSGBUF_SIZE];
	va_list ap;
	int cc;
	int offset;

	if (flags & ERR_NONAME)
		offset = 0;
	else
		offset = sprintf(buf, "%s: ", program_name);

	va_start(ap, fmt);
	cc = vsprintf(&buf[offset], gettext(fmt), ap);
	offset += cc;
	va_end(ap);

	if (flags & ERR_PERROR) {
		if (buf[offset-1] != ' ')
			(void) strcat(buf, " ");
		(void) strcat(buf, strerror(errno));
	}
	(void) fprintf(stderr, "%s\n", buf);
	if (flags & ERR_USAGE)
		usage();
	if (flags & ERR_FATAL)
		exit(1);
}


static void
usage(void)
{
	errmsg(ERR_NONAME,
	    "Usage: %s [-F FSType] [-abeghklmntPVvZ]"
	    " [-o FSType-specific_options]"
	    " [directory | block_device | resource]", program_name);
	exit(1);
	/* NOTREACHED */
}


static char *
new_string(char *s)
{
	char *p = NULL;

	if (s) {
		p = strdup(s);
		if (p)
			return (p);
		errmsg(ERR_FATAL, "out of memory");
		/* NOTREACHED */
	}
	return (p);
}


/*
 * Allocate memory using malloc but terminate if the allocation fails
 */
static void *
xmalloc(size_t size)
{
	void *p = malloc(size);

	if (p)
		return (p);
	errmsg(ERR_FATAL, "out of memory");
	/* NOTREACHED */
	return (NULL);
}


/*
 * Allocate memory using realloc but terminate if the allocation fails
 */
static void *
xrealloc(void *ptr, size_t size)
{
	void *p = realloc(ptr, size);

	if (p)
		return (p);
	errmsg(ERR_FATAL, "out of memory");
	/* NOTREACHED */
	return (NULL);
}


/*
 * fopen the specified file for reading but terminate if the fopen fails
 */
static FILE *
xfopen(char *file)
{
	FILE *fp = fopen(file, "r");

	if (fp == NULL)
		errmsg(ERR_FATAL + ERR_PERROR, "failed to open %s:", file);
	return (fp);
}


/*
 * Read remote file system types from REMOTE_FS into the
 * remote_fstypes array.
 */
static void
init_remote_fs(void)
{
	FILE	*fp;
	char	line_buf[LINEBUF_SIZE];
	size_t	fstype_index = 0;

	if ((fp = fopen(REMOTE_FS, "r")) == NULL) {
		errmsg(ERR_NOFLAGS,
		    "Warning: can't open %s, ignored", REMOTE_FS);
		return;
	}

	while (fgets(line_buf, sizeof (line_buf), fp) != NULL) {
		char buf[LINEBUF_SIZE];

		(void) sscanf(line_buf, "%s", buf);
		remote_fstypes[fstype_index++] = new_string(buf);

		if (fstype_index == N_FSTYPES)
			break;
	}
	(void) fclose(fp);
}


/*
 * Returns TRUE if fstype is a remote file system type;
 * otherwise, returns FALSE.
 */
static int
is_remote_fs(char *fstype)
{
	char **p;
	static bool_int remote_fs_initialized;

	if (! remote_fs_initialized) {
		init_remote_fs();
		remote_fs_initialized = TRUE;
	}

	for (p = remote_fstypes; *p; p++)
		if (EQ(fstype, *p))
			return (TRUE);
	return (FALSE);
}


static char *
basename(char *s)
{
	char *p = strrchr(s, '/');

	return (p ? p+1 : s);
}


/*
 * Create a new "struct extmnttab" and make sure that its fields point
 * to malloc'ed memory
 */
static struct extmnttab *
mntdup(struct extmnttab *old)
{
	struct extmnttab *new = NEW(struct extmnttab);

	new->mnt_special = new_string(old->mnt_special);
	new->mnt_mountp  = new_string(old->mnt_mountp);
	new->mnt_fstype  = new_string(old->mnt_fstype);
	new->mnt_mntopts = new_string(old->mnt_mntopts);
	new->mnt_time    = new_string(old->mnt_time);
	new->mnt_major   = old->mnt_major;
	new->mnt_minor   = old->mnt_minor;
	return (new);
}


static void
mtab_error(char *mtab_file, int status)
{
	if (status == MNT_TOOLONG)
		errmsg(ERR_NOFLAGS, "a line in %s exceeds %d characters",
		    mtab_file, MNT_LINE_MAX);
	else if (status == MNT_TOOMANY)
		errmsg(ERR_NOFLAGS,
		    "a line in %s has too many fields", mtab_file);
	else if (status == MNT_TOOFEW)
		errmsg(ERR_NOFLAGS,
		    "a line in %s has too few fields", mtab_file);
	else
		errmsg(ERR_NOFLAGS,
		    "error while reading %s: %d", mtab_file, status);
	exit(1);
	/* NOTREACHED */
}


/*
 * Read the mount table from the specified file.
 * We keep the table in memory for faster lookups.
 */
static void
mtab_read_file(void)
{
	char		*mtab_file = MOUNT_TAB;
	FILE		*fp;
	struct extmnttab	mtab;
	int		status;

	fp = xfopen(mtab_file);

	resetmnttab(fp);
	mount_table_allocated_entries = MOUNT_TABLE_ENTRIES;
	mount_table_entries = 0;
	mount_table = xmalloc(
	    mount_table_allocated_entries * sizeof (struct mtab_entry));

	while ((status = getextmntent(fp, &mtab, sizeof (struct extmnttab)))
	    == 0) {
		struct mtab_entry *mtep;

		if (mount_table_entries == mount_table_allocated_entries) {
			mount_table_allocated_entries += MOUNT_TABLE_ENTRIES;
			mount_table = xrealloc(mount_table,
			    mount_table_allocated_entries *
			    sizeof (struct mtab_entry));
		}
		mtep = &mount_table[mount_table_entries++];
		mtep->mte_mount = mntdup(&mtab);
		mtep->mte_dev_is_valid = FALSE;
		mtep->mte_ignore = (hasmntopt((struct mnttab *)&mtab,
		    MNTOPT_IGNORE) != NULL);
	}

	(void) fclose(fp);

	if (status == -1)			/* reached EOF */
		return;
	mtab_error(mtab_file, status);
	/* NOTREACHED */
}


/*
 * We use this macro when we want to record the option for the purpose of
 * passing it to the FS-specific df
 */
#define	SET_OPTION(opt)		opt##_option = TRUE, \
				df_options[df_options_len++] = arg

static void
parse_options(int argc, char *argv[])
{
	int arg;

	opterr = 0;	/* getopt shouldn't complain about unknown options */

	while ((arg = getopt(argc, argv, "F:o:abehkVtgnlmPvZ")) != EOF) {
		if (arg == 'F') {
			if (F_option)
				errmsg(ERR_FATAL + ERR_USAGE,
				    "more than one FSType specified");
			F_option = 1;
			FSType = optarg;
		} else if (arg == 'V' && ! V_option) {
			V_option = TRUE;
		} else if (arg == 'v' && ! v_option) {
			v_option = TRUE;
		} else if (arg == 'P' && ! P_option) {
			SET_OPTION(P);
		} else if (arg == 'a' && ! a_option) {
			SET_OPTION(a);
		} else if (arg == 'b' && ! b_option) {
			SET_OPTION(b);
		} else if (arg == 'e' && ! e_option) {
			SET_OPTION(e);
		} else if (arg == 'g' && ! g_option) {
			SET_OPTION(g);
		} else if (arg == 'h') {
			use_scaling = TRUE;
		} else if (arg == 'k' && ! k_option) {
			SET_OPTION(k);
		} else if (arg == 'l' && ! l_option) {
			SET_OPTION(l);
		} else if (arg == 'm' && ! m_option) {
			SET_OPTION(m);
		} else if (arg == 'n' && ! n_option) {
			SET_OPTION(n);
		} else if (arg == 't' && ! t_option) {
			SET_OPTION(t);
		} else if (arg == 'o') {
			if (o_option)
				errmsg(ERR_FATAL + ERR_USAGE,
				"the -o option can only be specified once");
			o_option = TRUE;
			o_option_arg = optarg;
		} else if (arg == 'Z') {
			SET_OPTION(Z);
		} else if (arg == '?') {
			errmsg(ERR_USAGE, "unknown option: %c", optopt);
		}
	}

	/*
	 * Option sanity checks
	 */
	if (g_option && o_option)
		errmsg(ERR_FATAL, "-o and -g options are incompatible");
	if (l_option && o_option)
		errmsg(ERR_FATAL, "-o and -l options are incompatible");
	if (n_option && o_option)
		errmsg(ERR_FATAL, "-o and -n options are incompatible");
	if (use_scaling && o_option)
		errmsg(ERR_FATAL, "-o and -h options are incompatible");
}



/*
 * Check if the user-specified argument is a resource name.
 * A resource name is whatever is placed in the mnt_special field of
 * struct mnttab. In the case of NFS, a resource name has the form
 * hostname:pathname
 * We try to find an exact match between the user-specified argument
 * and the mnt_special field of a mount table entry.
 * We also use the heuristic of removing the basename from the user-specified
 * argument and repeating the test until we get a match. This works
 * fine for NFS but may fail for other remote file system types. However,
 * it is guaranteed that the function will not fail if the user specifies
 * the exact resource name.
 * If successful, this function sets the 'dfr_mte' field of '*dfrp'
 */
static void
resource_mount_entry(struct df_request *dfrp)
{
	char *name;

	/*
	 * We need our own copy since we will modify the string
	 */
	name = new_string(dfrp->dfr_cmd_arg);

	for (;;) {
		char *p;
		int i;

		/*
		 * Compare against all known mount points.
		 * We start from the most recent mount, which is at the
		 * end of the array.
		 */
		for (i = mount_table_entries - 1; i >= 0; i--) {
			struct mtab_entry *mtep = &mount_table[i];

			if (EQ(name, mtep->mte_mount->mnt_special)) {
				dfrp->dfr_mte = mtep;
				break;
			}
		}

		/*
		 * Remove the last component of the pathname.
		 * If there is no such component, this is not a resource name.
		 */
		p = strrchr(name, '/');
		if (p == NULL)
			break;
		*p = NUL;
	}
}



/*
 * Try to match the command line argument which is a block special device
 * with the special device of one of the mounted file systems.
 * If one is found, set the appropriate field of 'dfrp' to the mount
 * table entry.
 */
static void
bdev_mount_entry(struct df_request *dfrp)
{
	int i;
	char *special = dfrp->dfr_cmd_arg;

	/*
	 * Compare against all known mount points.
	 * We start from the most recent mount, which is at the
	 * end of the array.
	 */
	for (i = mount_table_entries - 1; i >= 0; i--) {
		struct mtab_entry *mtep = &mount_table[i];

		if (EQ(special, mtep->mte_mount->mnt_special)) {
			dfrp->dfr_mte = mtep;
			break;
		}
	}
}

static struct mtab_entry *
devid_matches(int i, dev_t devno)
{
	struct mtab_entry	*mtep = &mount_table[i];
	struct extmnttab	*mtp = mtep->mte_mount;
	/* int	len = strlen(mtp->mnt_mountp); */

	if (EQ(mtp->mnt_fstype, MNTTYPE_SWAP))
		return (NULL);
	/*
	 * check if device numbers match. If there is a cached device number
	 * in the mtab_entry, use it, otherwise get the device number
	 * either from the mnttab entry or by stat'ing the mount point.
	 */
	if (! mtep->mte_dev_is_valid) {
		struct stat64 st;
		dev_t dev = NODEV;

		dev = makedev(mtp->mnt_major, mtp->mnt_minor);
		if (dev == 0)
			dev = NODEV;
		if (dev == NODEV) {
			if (stat64(mtp->mnt_mountp, &st) == -1) {
				return (NULL);
			} else {
				dev = st.st_dev;
			}
		}
		mtep->mte_dev = dev;
		mtep->mte_dev_is_valid = TRUE;
	}
	if (mtep->mte_dev == devno) {
		return (mtep);
	}
	return (NULL);
}

/*
 * Find the mount point under which the user-specified path resides
 * and set the 'dfr_mte' field of '*dfrp' to point to the mount table entry.
 */
static void
path_mount_entry(struct df_request *dfrp, dev_t devno)
{
	char			dirpath[MAXPATHLEN];
	char			*dir = dfrp->dfr_cmd_arg;
	struct mtab_entry	*match, *tmatch;
	int i;

	/*
	 * Expand the given path to get a canonical version (i.e. an absolute
	 * path without symbolic links).
	 */
	if (realpath(dir, dirpath) == NULL) {
		errmsg(ERR_PERROR, "cannot canonicalize %s:", dir);
		return;
	}
	/*
	 * If the mnt point is lofs, search from the top of entries from
	 * /etc/mnttab and return the entry that best matches the pathname.
	 * For non-lofs mount points, return the first entry from the bottom
	 * of the entries in /etc/mnttab that matches on the devid field
	 */
	match = NULL;
	if (dfrp->dfr_fstype && EQ(dfrp->dfr_fstype, MNTTYPE_LOFS)) {
		struct extmnttab *entryp;
		char *path, *mountp;
		char p, m;
		int score;
		int best_score = 0;
		int best_index = -1;

		for (i = 0; i < mount_table_entries; i++) {
			entryp = mount_table[i].mte_mount;

			if (!EQ(entryp->mnt_fstype, MNTTYPE_LOFS))
				continue;

			path = dirpath;
			mountp = entryp->mnt_mountp;
			score = 0;
			/*
			 * Count the number of matching characters
			 * until either path or mountpoint is exhausted
			 */
			while ((p = *path++) == (m = *mountp++)) {
				score++;

				if (p == '\0' || m == '\0')
					break;
			}

			/* Both exhausted so we have a match */
			if (p == '\0' && m == '\0') {
				best_index = i;
				break;
			}

			/*
			 * We have exhausted the mountpoint and the current
			 * character in the path is a '/' hence the full path
			 * traverses this mountpoint.
			 * Record this as the best candidate so far.
			 */
			if (p == '/' && m == '\0') {
				if (score > best_score) {
					best_index = i;
					best_score = score;
				}
			}
		}

		if (best_index > -1)
			match = &mount_table[best_index];
	} else {
		for (i = mount_table_entries - 1; i >= 0; i--) {
			if (tmatch = devid_matches(i, devno)) {
				/*
				 * If executing in a zone, there might be lofs
				 * mounts for which the real mount point is
				 * invisible; accept the "best fit" for this
				 * devid.
				 */
				match = tmatch;
				if (!EQ(match->mte_mount->mnt_fstype,
				    MNTTYPE_LOFS)) {
					break;
				}
			}
		}
	}
	if (! match) {
		errmsg(ERR_NOFLAGS,
		    "Could not find mount point for %s", dir);
		return;
	}
	dfrp->dfr_mte = match;
}

/*
 * Execute a single FS-specific df command for all given requests
 * Return 0 if successful, 1 otherwise.
 */
static int
run_fs_specific_df(struct df_request request_list[], int entries)
{
	int	i;
	int	argv_index;
	char	**argv;
	size_t	size;
	pid_t	pid;
	int	status;
	char	cmd_path[MAXPATHLEN];
	char	*fstype;

	if (entries == 0)
		return (0);

	fstype = request_list[0].dfr_fstype;

	if (F_option && ! EQ(FSType, fstype))
		return (0);

	(void) sprintf(cmd_path, "%s%s/df", FS_LIBPATH, fstype);
	/*
	 * Argv entries:
	 *		1 for the path
	 *		2 for -o <options>
	 *		1 for the generic options that we propagate
	 *		1 for the terminating NULL pointer
	 *		n for the number of user-specified arguments
	 */
	size = (5 + entries) * sizeof (char *);
	argv = xmalloc(size);
	(void) memset(argv, 0, size);

	argv[0] = cmd_path;
	argv_index = 1;
	if (o_option) {
		argv[argv_index++] = "-o";
		argv[argv_index++] = o_option_arg;
	}

	/*
	 * Check if we need to propagate any generic options
	 */
	if (df_options_len > 1)
		argv[argv_index++] = df_options;

	/*
	 * If there is a user-specified path, we pass that to the
	 * FS-specific df. Otherwise, we are guaranteed to have a mount
	 * point, since a request without a user path implies that
	 * we are reporting only on mounted file systems.
	 */
	for (i = 0; i < entries; i++) {
		struct df_request *dfrp = &request_list[i];

		argv[argv_index++] = (dfrp->dfr_cmd_arg == NULL)
		    ? DFR_MOUNT_POINT(dfrp)
		    : dfrp->dfr_cmd_arg;
	}

	if (V_option) {
		for (i = 0; i < argv_index-1; i++)
			(void) printf("%s ", argv[i]);
		(void) printf("%s\n", argv[i]);
		return (0);
	}

	pid = fork();

	if (pid == -1) {
		errmsg(ERR_PERROR, "cannot fork process:");
		return (1);
	} else if (pid == 0) {
		(void) execv(cmd_path, argv);
		if (errno == ENOENT)
			errmsg(ERR_NOFLAGS,
			    "operation not applicable for FSType %s",
			    fstype);
		else
			errmsg(ERR_PERROR, "cannot execute %s:", cmd_path);
		exit(2);
	}

	/*
	 * Reap the child
	 */
	for (;;) {
		pid_t wpid = waitpid(pid, &status, 0);

		if (wpid == -1)
			if (errno == EINTR)
				continue;
			else {
				errmsg(ERR_PERROR, "waitpid error:");
				return (1);
			}
		else
			break;
	}

	return ((WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : 1);
}



/*
 * Remove from the request list all requests that do not apply.
 * Notice that the subsequent processing of the requests depends on
 * the sanity checking performed by this function.
 */
static int
prune_list(struct df_request request_list[],
    size_t n_requests, size_t *valid_requests)
{
	size_t	i;
	size_t	n_valid = 0;
	int	errors = 0;

	for (i = 0; i < n_requests; i++) {
		struct df_request *dfrp = &request_list[i];

		/*
		 * Skip file systems that are not mounted if either the
		 * -l or -n options were specified. If none of these options
		 * are present, the appropriate FS-specific df will be invoked.
		 */
		if (! DFR_ISMOUNTEDFS(dfrp)) {
			if (l_option || n_option) {
				errmsg(ERR_NOFLAGS,
				    "%s option incompatible with unmounted "
				    "special device (%s)",
				    l_option ? "-l" : "-n", dfrp->dfr_cmd_arg);
				dfrp->dfr_valid = FALSE;
				errors++;
			}
			else
				n_valid++;
			continue;
		}

		/*
		 * Check for inconsistency between the argument of -F and
		 * the actual file system type.
		 * If there is an inconsistency and the user specified a
		 * path, this is an error since we are asked to interpret
		 * the path using the wrong file system type. If there is
		 * no path associated with this request, we quietly ignore it.
		 */
		if (F_option && ! EQ(dfrp->dfr_fstype, FSType)) {
			dfrp->dfr_valid = FALSE;
			if (dfrp->dfr_cmd_arg != NULL) {
				errmsg(ERR_NOFLAGS,
				"Warning: %s mounted as a %s file system",
				    dfrp->dfr_cmd_arg, dfrp->dfr_fstype);
				errors++;
			}
			continue;
		}

		/*
		 * Skip remote file systems if the -l option is present
		 */
		if (l_option && is_remote_fs(dfrp->dfr_fstype)) {
			if (dfrp->dfr_cmd_arg != NULL) {
				errmsg(ERR_NOFLAGS,
				    "Warning: %s is not a local file system",
				    dfrp->dfr_cmd_arg);
				errors++;
			}
			dfrp->dfr_valid = FALSE;
			continue;
		}

		/*
		 * Skip file systems mounted as "ignore" unless the -a option
		 * is present, or the user explicitly specified them on
		 * the command line.
		 */
		if (dfrp->dfr_mte->mte_ignore &&
		    ! (a_option || dfrp->dfr_cmd_arg)) {
			dfrp->dfr_valid = FALSE;
			continue;
		}

		n_valid++;
	}
	*valid_requests = n_valid;
	return (errors);
}


/*
 * Print the appropriate header for the requested output format.
 * Options are checked in order of their precedence.
 */
static void
print_header(void)
{
	if (use_scaling) { /* this comes from the -h option */
		int arg = 'h';

		(void) printf("%-*s %*s %*s %*s %-*s %s\n",
		    FILESYSTEM_WIDTH, TRANSLATE("Filesystem"),
		    SCALED_WIDTH, TRANSLATE("Size"),
		    SCALED_WIDTH, TRANSLATE("Used"),
		    AVAILABLE_WIDTH, TRANSLATE("Available"),
		    CAPACITY_WIDTH, TRANSLATE("Capacity"),
		    TRANSLATE("Mounted on"));
		SET_OPTION(h);
		return;
	}
	if (k_option) {
		int arg = 'h';

		(void) printf(gettext("%-*s %*s %*s %*s %-*s %s\n"),
		    FILESYSTEM_WIDTH, TRANSLATE("Filesystem"),
		    KBYTE_WIDTH, TRANSLATE("1024-blocks"),
		    KBYTE_WIDTH, TRANSLATE("Used"),
		    KBYTE_WIDTH, TRANSLATE("Available"),
		    CAPACITY_WIDTH, TRANSLATE("Capacity"),
		    TRANSLATE("Mounted on"));
		SET_OPTION(h);
		return;
	}
	if (m_option) {
		int arg = 'h';

		(void) printf(gettext("%-*s %*s %*s %*s %-*s %s\n"),
		    FILESYSTEM_WIDTH, TRANSLATE("Filesystem"),
		    KBYTE_WIDTH, TRANSLATE("1M-blocks"),
		    KBYTE_WIDTH, TRANSLATE("Used"),
		    KBYTE_WIDTH, TRANSLATE("Available"),
		    CAPACITY_WIDTH, TRANSLATE("Capacity"),
		    TRANSLATE("Mounted on"));
		SET_OPTION(h);
		return;
	}
	/* Added for XCU4 compliance */
	if (P_option) {
		int arg = 'h';

		(void) printf(gettext("%-*s %*s %*s %*s %-*s %s\n"),
		    FILESYSTEM_WIDTH, TRANSLATE("Filesystem"),
		    KBYTE_WIDTH, TRANSLATE("512-blocks"),
		    KBYTE_WIDTH, TRANSLATE("Used"),
		    KBYTE_WIDTH, TRANSLATE("Available"),
		    CAPACITY_WIDTH, TRANSLATE("Capacity"),
		    TRANSLATE("Mounted on"));

		SET_OPTION(h);
		return;
	}
	/* End XCU4 */
	if (v_option) {
		(void) printf("%-*s %-*s %*s %*s %*s %-*s\n",
		    IBCS2_MOUNT_POINT_WIDTH, TRANSLATE("Mount Dir"),
		    IBCS2_FILESYSTEM_WIDTH, TRANSLATE("Filesystem"),
		    BLOCK_WIDTH, TRANSLATE("blocks"),
		    BLOCK_WIDTH, TRANSLATE("used"),
		    BLOCK_WIDTH, TRANSLATE("free"),
		    CAPACITY_WIDTH, TRANSLATE(" %used"));
		return;
	}
	if (e_option) {
		(void) printf(gettext("%-*s %*s\n"),
		    FILESYSTEM_WIDTH, TRANSLATE("Filesystem"),
		    BLOCK_WIDTH, TRANSLATE("ifree"));
		return;
	}
	if (b_option) {
		(void) printf(gettext("%-*s %*s\n"),
		    FILESYSTEM_WIDTH, TRANSLATE("Filesystem"),
		    BLOCK_WIDTH, TRANSLATE("avail"));
		return;
	}
}


/*
 * Convert an unsigned long long to a string representation and place the
 * result in the caller-supplied buffer.
 * The given number is in units of "unit_from" size, but the
 * converted number will be in units of "unit_to" size. The unit sizes
 * must be powers of 2.
 * The value "(unsigned long long)-1" is a special case and is always
 * converted to "-1".
 * Returns a pointer to the caller-supplied buffer.
 */
static char *
number_to_string(
			char *buf,		/* put the result here */
			unsigned long long number, /* convert this number */
			int unit_from,		/* from units of this size */
			int unit_to)		/* to units of this size */
{
	if ((long long)number == (long long)-1)
		(void) strcpy(buf, "-1");
	else {
		if (unit_from == unit_to)
			(void) sprintf(buf, "%llu", number);
		else if (unit_from < unit_to)
			(void) sprintf(buf, "%llu",
			    number / (unsigned long long)(unit_to / unit_from));
		else
			(void) sprintf(buf, "%llu",
			    number * (unsigned long long)(unit_from / unit_to));
	}
	return (buf);
}

/*
 * The statvfs() implementation allows us to return only two values, the total
 * number of blocks and the number of blocks free.  The equation 'used = total -
 * free' will not work for ZFS filesystems, due to the nature of pooled storage.
 * We choose to return values in the statvfs structure that will produce correct
 * results for 'used' and 'available', but not 'total'.  This function will open
 * the underlying ZFS dataset if necessary and get the real value.
 */
static void
adjust_total_blocks(struct df_request *dfrp, fsblkcnt64_t *total,
    uint64_t blocksize)
{
	char *dataset, *slash;
	boolean_t first = TRUE;
	uint64_t quota = 0;

	if (strcmp(DFR_FSTYPE(dfrp), MNTTYPE_ZFS) != 0 || !load_libzfs())
		return;

	/*
	 * We want to get the total size for this filesystem as bounded by any
	 * quotas. In order to do this, we start at the current filesystem and
	 * work upwards looking for the smallest quota.  When we reach the
	 * pool itself, the quota is the amount used plus the amount
	 * available.
	 */
	if ((dataset = strdup(DFR_SPECIAL(dfrp))) == NULL)
		return;

	slash = dataset + strlen(dataset);
	while (slash != NULL) {
		zfs_handle_t *zhp;
		uint64_t this_quota;

		*slash = '\0';

		zhp = _zfs_open(g_zfs, dataset, ZFS_TYPE_DATASET);
		if (zhp == NULL)
			break;

		/* true at first iteration of loop */
		if (first) {
			quota = _zfs_prop_get_int(zhp, ZFS_PROP_REFQUOTA);
			if (quota == 0)
				quota = UINT64_MAX;
			first = FALSE;
		}

		this_quota = _zfs_prop_get_int(zhp, ZFS_PROP_QUOTA);
		if (this_quota && this_quota < quota)
			quota = this_quota;

		/* true at last iteration of loop */
		if ((slash = strrchr(dataset, '/')) == NULL) {
			uint64_t size;

			size = _zfs_prop_get_int(zhp, ZFS_PROP_USED) +
			    _zfs_prop_get_int(zhp, ZFS_PROP_AVAILABLE);
			if (size < quota)
				quota = size;
		}

		_zfs_close(zhp);
	}

	/*
	 * Modify total only if we managed to get some stats from libzfs.
	 */
	if (quota != 0)
		*total = quota / blocksize;
	free(dataset);
}

/*
 * The output will appear properly columnized regardless of the names of
 * the various fields
 */
static void
g_output(struct df_request *dfrp, struct statvfs64 *fsp)
{
	fsblkcnt64_t	available_blocks	= fsp->f_bavail;
	fsblkcnt64_t	total_blocks = fsp->f_blocks;
	numbuf_t	total_blocks_buf;
	numbuf_t	total_files_buf;
	numbuf_t	free_blocks_buf;
	numbuf_t	available_blocks_buf;
	numbuf_t	free_files_buf;
	numbuf_t	fname_buf;
	char		*temp_buf;

#define	DEFINE_STR_LEN(var)			\
	static char *var##_str;			\
	static size_t var##_len

#define	SET_STR_LEN(name, var)\
	if (! var##_str) {\
		var##_str = TRANSLATE(name); \
		var##_len = strlen(var##_str); \
	}

	DEFINE_STR_LEN(block_size);
	DEFINE_STR_LEN(frag_size);
	DEFINE_STR_LEN(total_blocks);
	DEFINE_STR_LEN(free_blocks);
	DEFINE_STR_LEN(available);
	DEFINE_STR_LEN(total_files);
	DEFINE_STR_LEN(free_files);
	DEFINE_STR_LEN(fstype);
	DEFINE_STR_LEN(fsys_id);
	DEFINE_STR_LEN(fname);
	DEFINE_STR_LEN(flag);

	/*
	 * TRANSLATION_NOTE
	 * The first argument of each of the following macro invocations is a
	 * string that needs to be translated.
	 */
	SET_STR_LEN("block size", block_size);
	SET_STR_LEN("frag size", frag_size);
	SET_STR_LEN("total blocks", total_blocks);
	SET_STR_LEN("free blocks", free_blocks);
	SET_STR_LEN("available", available);
	SET_STR_LEN("total files", total_files);
	SET_STR_LEN("free files", free_files);
	SET_STR_LEN("fstype", fstype);
	SET_STR_LEN("filesys id", fsys_id);
	SET_STR_LEN("filename length", fname);
	SET_STR_LEN("flag", flag);

#define	NCOL1_WIDTH	(int)MAX3(BLOCK_WIDTH, NFILES_WIDTH, FSTYPE_WIDTH)
#define	NCOL2_WIDTH	(int)MAX3(BLOCK_WIDTH, FSID_WIDTH, FLAG_WIDTH) + 2
#define	NCOL3_WIDTH	(int)MAX3(BSIZE_WIDTH, BLOCK_WIDTH, NAMELEN_WIDTH)
#define	NCOL4_WIDTH	(int)MAX(FRAGSIZE_WIDTH, NFILES_WIDTH)

#define	SCOL1_WIDTH	(int)MAX3(total_blocks_len, free_files_len, fstype_len)
#define	SCOL2_WIDTH	(int)MAX3(free_blocks_len, fsys_id_len, flag_len)
#define	SCOL3_WIDTH	(int)MAX3(block_size_len, available_len, fname_len)
#define	SCOL4_WIDTH	(int)MAX(frag_size_len, total_files_len)

	temp_buf = xmalloc(
	    MAX(MOUNT_POINT_WIDTH, strlen(DFR_MOUNT_POINT(dfrp)))
	    + MAX(SPECIAL_DEVICE_WIDTH, strlen(DFR_SPECIAL(dfrp)))
	    + 20); /* plus slop - nulls & formatting */
	(void) sprintf(temp_buf, "%-*s(%-*s):",
	    MOUNT_POINT_WIDTH, DFR_MOUNT_POINT(dfrp),
	    SPECIAL_DEVICE_WIDTH, DFR_SPECIAL(dfrp));

	(void) printf("%-*s %*lu %-*s %*lu %-*s\n",
	    NCOL1_WIDTH + 1 + SCOL1_WIDTH + 1 + NCOL2_WIDTH + 1 +  SCOL2_WIDTH,
	    temp_buf,
	    NCOL3_WIDTH, fsp->f_bsize, SCOL3_WIDTH, block_size_str,
	    NCOL4_WIDTH, fsp->f_frsize, SCOL4_WIDTH, frag_size_str);
	free(temp_buf);

	/*
	 * Adjust available_blocks value -  it can be less than 0 on
	 * a 4.x file system. Reset it to 0 in order to avoid printing
	 * negative numbers.
	 */
	if ((long long)available_blocks < (long long)0)
		available_blocks = (fsblkcnt64_t)0;

	adjust_total_blocks(dfrp, &total_blocks, fsp->f_frsize);

	(void) printf("%*s %-*s %*s %-*s %*s %-*s %*s %-*s\n",
	    NCOL1_WIDTH, number_to_string(total_blocks_buf,
	    total_blocks, fsp->f_frsize, 512),
	    SCOL1_WIDTH, total_blocks_str,
	    NCOL2_WIDTH, number_to_string(free_blocks_buf,
	    fsp->f_bfree, fsp->f_frsize, 512),
	    SCOL2_WIDTH, free_blocks_str,
	    NCOL3_WIDTH, number_to_string(available_blocks_buf,
	    available_blocks, fsp->f_frsize, 512),
	    SCOL3_WIDTH, available_str,
	    NCOL4_WIDTH, number_to_string(total_files_buf,
	    fsp->f_files, 1, 1),
	    SCOL4_WIDTH, total_files_str);

	(void) printf("%*s %-*s %*lu %-*s %s\n",
	    NCOL1_WIDTH, number_to_string(free_files_buf,
	    fsp->f_ffree, 1, 1),
	    SCOL1_WIDTH, free_files_str,
	    NCOL2_WIDTH, fsp->f_fsid, SCOL2_WIDTH, fsys_id_str,
	    fsp->f_fstr);

	(void) printf("%*s %-*s %#*.*lx %-*s %*s %-*s\n\n",
	    NCOL1_WIDTH, fsp->f_basetype, SCOL1_WIDTH, fstype_str,
	    NCOL2_WIDTH, NCOL2_WIDTH-2, fsp->f_flag, SCOL2_WIDTH, flag_str,
	    NCOL3_WIDTH, number_to_string(fname_buf,
	    (unsigned long long)fsp->f_namemax, 1, 1),
	    SCOL3_WIDTH, fname_str);
}


static void
k_output(struct df_request *dfrp, struct statvfs64 *fsp)
{
	fsblkcnt64_t total_blocks		= fsp->f_blocks;
	fsblkcnt64_t	free_blocks		= fsp->f_bfree;
	fsblkcnt64_t	available_blocks	= fsp->f_bavail;
	fsblkcnt64_t	used_blocks;
	char 		*file_system		= DFR_SPECIAL(dfrp);
	numbuf_t	total_blocks_buf;
	numbuf_t	used_blocks_buf;
	numbuf_t	available_blocks_buf;
	char 		capacity_buf[LINEBUF_SIZE];

	/*
	 * If the free block count is -1, don't trust anything but the total
	 * number of blocks.
	 */
	if (free_blocks == (fsblkcnt64_t)-1) {
		used_blocks = (fsblkcnt64_t)-1;
		(void) strcpy(capacity_buf, "  100%");
	} else {
		fsblkcnt64_t reserved_blocks = free_blocks - available_blocks;

		used_blocks	= total_blocks - free_blocks;

		/*
		 * The capacity estimation is bogus when available_blocks is 0
		 * and the super-user has allocated more space. The reason
		 * is that reserved_blocks is inaccurate in that case, because
		 * when the super-user allocates space, free_blocks is updated
		 * but available_blocks is not (since it can't drop below 0).
		 *
		 * XCU4 and POSIX.2 require that any fractional result of the
		 * capacity estimation be rounded to the next highest integer,
		 * hence the addition of 0.5.
		 */
		(void) sprintf(capacity_buf, "%5.0f%%",
		    (total_blocks == 0) ? 0.0 :
		    ((double)used_blocks /
		    (double)(total_blocks - reserved_blocks))
		    * 100.0 + 0.5);
	}

	/*
	 * The available_blocks can be less than 0 on a 4.x file system.
	 * Reset it to 0 in order to avoid printing negative numbers.
	 */
	if ((long long)available_blocks < (long long)0)
		available_blocks = (fsblkcnt64_t)0;
	/*
	 * Print long special device names (usually NFS mounts) in a line
	 * by themselves when the output is directed to a terminal.
	 */
	if (tty_output && strlen(file_system) > (size_t)FILESYSTEM_WIDTH) {
		(void) printf("%s\n", file_system);
		file_system = "";
	}

	adjust_total_blocks(dfrp, &total_blocks, fsp->f_frsize);

	if (use_scaling) { /* comes from the -h option */
		nicenum_scale(total_blocks, fsp->f_frsize,
		    total_blocks_buf, sizeof (total_blocks_buf), 0);
		nicenum_scale(used_blocks, fsp->f_frsize,
		    used_blocks_buf, sizeof (used_blocks_buf), 0);
		nicenum_scale(available_blocks, fsp->f_frsize,
		    available_blocks_buf, sizeof (available_blocks_buf), 0);

		(void) printf("%-*s %*s %*s %*s %-*s %-s\n",
		    FILESYSTEM_WIDTH, file_system,
		    SCALED_WIDTH, total_blocks_buf,
		    SCALED_WIDTH, used_blocks_buf,
		    AVAILABLE_WIDTH, available_blocks_buf,
		    CAPACITY_WIDTH, capacity_buf, DFR_MOUNT_POINT(dfrp));
		return;
	}

	if (v_option) {
	(void) printf("%-*.*s %-*.*s %*lld %*lld %*lld %-.*s\n",
	    IBCS2_MOUNT_POINT_WIDTH, IBCS2_MOUNT_POINT_WIDTH,
	    DFR_MOUNT_POINT(dfrp),
	    IBCS2_FILESYSTEM_WIDTH, IBCS2_FILESYSTEM_WIDTH, file_system,
	    BLOCK_WIDTH, total_blocks,
	    BLOCK_WIDTH, used_blocks,
	    BLOCK_WIDTH, available_blocks,
	    CAPACITY_WIDTH,	capacity_buf);
		return;
	}

	if (P_option && !k_option && !m_option) {
	(void) printf("%-*s %*s %*s %*s %-*s %-s\n",
	    FILESYSTEM_WIDTH, file_system,
	    KBYTE_WIDTH, number_to_string(total_blocks_buf,
	    total_blocks, fsp->f_frsize, 512),
	    KBYTE_WIDTH, number_to_string(used_blocks_buf,
	    used_blocks, fsp->f_frsize, 512),
	    KBYTE_WIDTH, number_to_string(available_blocks_buf,
	    available_blocks, fsp->f_frsize, 512),
	    CAPACITY_WIDTH, capacity_buf,
	    DFR_MOUNT_POINT(dfrp));
	} else if (m_option) {
	(void) printf("%-*s %*s %*s %*s %-*s %-s\n",
	    FILESYSTEM_WIDTH, file_system,
	    KBYTE_WIDTH, number_to_string(total_blocks_buf,
	    total_blocks, fsp->f_frsize, 1024*1024),
	    KBYTE_WIDTH, number_to_string(used_blocks_buf,
	    used_blocks, fsp->f_frsize, 1024*1024),
	    KBYTE_WIDTH, number_to_string(available_blocks_buf,
	    available_blocks, fsp->f_frsize, 1024*1024),
	    CAPACITY_WIDTH,	capacity_buf,
	    DFR_MOUNT_POINT(dfrp));
	} else {
	(void) printf("%-*s %*s %*s %*s %-*s %-s\n",
	    FILESYSTEM_WIDTH, file_system,
	    KBYTE_WIDTH, number_to_string(total_blocks_buf,
	    total_blocks, fsp->f_frsize, 1024),
	    KBYTE_WIDTH, number_to_string(used_blocks_buf,
	    used_blocks, fsp->f_frsize, 1024),
	    KBYTE_WIDTH, number_to_string(available_blocks_buf,
	    available_blocks, fsp->f_frsize, 1024),
	    CAPACITY_WIDTH,	capacity_buf,
	    DFR_MOUNT_POINT(dfrp));
	}
}

/*
 * The following is for internationalization support.
 */
static bool_int strings_initialized;
static char 	*files_str;
static char	*blocks_str;
static char	*total_str;
static char	*kilobytes_str;

static void
strings_init(void)
{
	total_str = TRANSLATE("total");
	files_str = TRANSLATE("files");
	blocks_str = TRANSLATE("blocks");
	kilobytes_str = TRANSLATE("kilobytes");
	strings_initialized = TRUE;
}

#define	STRINGS_INIT()		if (!strings_initialized) strings_init()


static void
t_output(struct df_request *dfrp, struct statvfs64 *fsp)
{
	fsblkcnt64_t	total_blocks = fsp->f_blocks;
	numbuf_t	total_blocks_buf;
	numbuf_t	total_files_buf;
	numbuf_t	free_blocks_buf;
	numbuf_t	free_files_buf;

	STRINGS_INIT();

	adjust_total_blocks(dfrp, &total_blocks, fsp->f_frsize);

	(void) printf("%-*s(%-*s): %*s %s %*s %s\n",
	    MOUNT_POINT_WIDTH, DFR_MOUNT_POINT(dfrp),
	    SPECIAL_DEVICE_WIDTH, DFR_SPECIAL(dfrp),
	    BLOCK_WIDTH, number_to_string(free_blocks_buf,
	    fsp->f_bfree, fsp->f_frsize, 512),
	    blocks_str,
	    NFILES_WIDTH, number_to_string(free_files_buf,
	    fsp->f_ffree, 1, 1),
	    files_str);
	/*
	 * The total column used to use the same space as the mnt pt & special
	 * dev fields. However, this doesn't work with massive special dev
	 * fields * (eg > 500 chars) causing an enormous amount of white space
	 * before the total column (see bug 4100411). So the code was
	 * simplified to set the total column at the usual gap.
	 * This had the side effect of fixing a bug where the previously
	 * used static buffer was overflowed by the same massive special dev.
	 */
	(void) printf("%*s: %*s %s %*s %s\n",
	    MNT_SPEC_WIDTH, total_str,
	    BLOCK_WIDTH, number_to_string(total_blocks_buf,
	    total_blocks, fsp->f_frsize, 512),
	    blocks_str,
	    NFILES_WIDTH, number_to_string(total_files_buf,
	    fsp->f_files, 1, 1),
	    files_str);
}


static void
eb_output(struct df_request *dfrp, struct statvfs64 *fsp)
{
	numbuf_t free_files_buf;
	numbuf_t free_kbytes_buf;

	STRINGS_INIT();

	(void) printf("%-*s(%-*s): %*s %s\n",
	    MOUNT_POINT_WIDTH, DFR_MOUNT_POINT(dfrp),
	    SPECIAL_DEVICE_WIDTH, DFR_SPECIAL(dfrp),
	    MAX(KBYTE_WIDTH, NFILES_WIDTH),
	    number_to_string(free_kbytes_buf,
	    fsp->f_bfree, fsp->f_frsize, 1024),
	    kilobytes_str);
	(void) printf("%-*s(%-*s): %*s %s\n",
	    MOUNT_POINT_WIDTH, DFR_MOUNT_POINT(dfrp),
	    SPECIAL_DEVICE_WIDTH, DFR_SPECIAL(dfrp),
	    MAX(NFILES_WIDTH, NFILES_WIDTH),
	    number_to_string(free_files_buf, fsp->f_ffree, 1, 1),
	    files_str);
}


static void
e_output(struct df_request *dfrp, struct statvfs64 *fsp)
{
	numbuf_t free_files_buf;

	(void) printf("%-*s %*s\n",
	    FILESYSTEM_WIDTH, DFR_SPECIAL(dfrp),
	    NFILES_WIDTH,
	    number_to_string(free_files_buf, fsp->f_ffree, 1, 1));
}


static void
b_output(struct df_request *dfrp, struct statvfs64 *fsp)
{
	numbuf_t free_blocks_buf;

	(void) printf("%-*s %*s\n",
	    FILESYSTEM_WIDTH, DFR_SPECIAL(dfrp),
	    BLOCK_WIDTH, number_to_string(free_blocks_buf,
	    fsp->f_bfree, fsp->f_frsize, 1024));
}


/* ARGSUSED */
static void
n_output(struct df_request *dfrp, struct statvfs64 *fsp)
{
	(void) printf("%-*s: %-*s\n",
	    MOUNT_POINT_WIDTH, DFR_MOUNT_POINT(dfrp),
	    FSTYPE_WIDTH, dfrp->dfr_fstype);
}


static void
default_output(struct df_request *dfrp, struct statvfs64 *fsp)
{
	numbuf_t free_blocks_buf;
	numbuf_t free_files_buf;

	STRINGS_INIT();

	(void) printf("%-*s(%-*s):%*s %s %*s %s\n",
	    MOUNT_POINT_WIDTH, DFR_MOUNT_POINT(dfrp),
	    SPECIAL_DEVICE_WIDTH, DFR_SPECIAL(dfrp),
	    BLOCK_WIDTH, number_to_string(free_blocks_buf,
	    fsp->f_bfree, fsp->f_frsize, 512),
	    blocks_str,
	    NFILES_WIDTH, number_to_string(free_files_buf,
	    fsp->f_ffree, 1, 1),
	    files_str);
}


/* ARGSUSED */
static void
V_output(struct df_request *dfrp, struct statvfs64 *fsp)
{
	char temp_buf[LINEBUF_SIZE];

	if (df_options_len > 1)
		(void) strcat(strcpy(temp_buf, df_options), " ");
	else
		temp_buf[0] = NUL;

	(void) printf("%s -F %s %s%s\n",
	    program_name, dfrp->dfr_fstype, temp_buf,
	    dfrp->dfr_cmd_arg ? dfrp->dfr_cmd_arg: DFR_SPECIAL(dfrp));
}


/*
 * This function is used to sort the array of df_requests according to fstype
 */
static int
df_reqcomp(const void *p1, const void *p2)
{
	int v = strcmp(DFRP(p1)->dfr_fstype, DFRP(p2)->dfr_fstype);

	if (v != 0)
		return (v);
	else
		return (DFRP(p1)->dfr_index - DFRP(p2)->dfr_index);
}


static void
vfs_error(char *file, int status)
{
	if (status == VFS_TOOLONG)
		errmsg(ERR_NOFLAGS, "a line in %s exceeds %d characters",
		    file, MNT_LINE_MAX);
	else if (status == VFS_TOOMANY)
		errmsg(ERR_NOFLAGS, "a line in %s has too many fields", file);
	else if (status == VFS_TOOFEW)
		errmsg(ERR_NOFLAGS, "a line in %s has too few fields", file);
	else
		errmsg(ERR_NOFLAGS, "error while reading %s: %d", file, status);
}


/*
 * Try to determine the fstype for the specified block device.
 * Return in order of decreasing preference:
 *	file system type from vfstab
 *	file system type as specified by -F option
 *	default file system type
 */
static char *
find_fstype(char *special)
{
	struct vfstab	vtab;
	FILE		*fp;
	int		status;
	char		*vfstab_file = VFS_TAB;

	fp = xfopen(vfstab_file);
	status = getvfsspec(fp, &vtab, special);
	(void) fclose(fp);
	if (status > 0)
		vfs_error(vfstab_file, status);

	if (status == 0) {
		if (F_option && ! EQ(FSType, vtab.vfs_fstype))
			errmsg(ERR_NOFLAGS,
			"warning: %s is of type %s", special, vtab.vfs_fstype);
		return (new_string(vtab.vfs_fstype));
	}
	else
		return (F_option ? FSType : default_fstype(special));
}

/*
 * When this function returns, the following fields are filled for all
 * valid entries in the requests[] array:
 *		dfr_mte		(if the file system is mounted)
 *		dfr_fstype
 *		dfr_index
 *
 * The function returns the number of errors that occurred while building
 * the request list.
 */
static int
create_request_list(
			int argc,
			char *argv[],
			struct df_request *requests_p[],
			size_t *request_count)
{
	struct df_request	*requests;
	struct df_request	*dfrp;
	size_t			size;
	size_t 			i;
	size_t 			request_index = 0;
	size_t			max_requests;
	int			errors = 0;

	/*
	 * If no args, use the mounted file systems, otherwise use the
	 * user-specified arguments.
	 */
	if (argc == 0) {
		mtab_read_file();
		max_requests = mount_table_entries;
	} else
		max_requests = argc;

	size = max_requests * sizeof (struct df_request);
	requests = xmalloc(size);
	(void) memset(requests, 0, size);

	if (argc == 0) {
		/*
		 * If -Z wasn't specified, we skip mounts in other
		 * zones.  This obviously is a noop in a non-global
		 * zone.
		 */
		boolean_t showall = (getzoneid() != GLOBAL_ZONEID) || Z_option;
		struct zone_summary *zsp;

		if (!showall) {
			zsp = fs_get_zone_summaries();
			if (zsp == NULL)
				errmsg(ERR_FATAL,
				    "unable to retrieve list of zones");
		}

		for (i = 0; i < mount_table_entries; i++) {
			struct extmnttab *mtp = mount_table[i].mte_mount;

			if (EQ(mtp->mnt_fstype, MNTTYPE_SWAP))
				continue;

			if (!showall) {
				if (fs_mount_in_other_zone(zsp,
				    mtp->mnt_mountp))
					continue;
			}
			dfrp = &requests[request_index++];
			dfrp->dfr_mte		= &mount_table[i];
			dfrp->dfr_fstype	= mtp->mnt_fstype;
			dfrp->dfr_index		= i;
			dfrp->dfr_valid		= TRUE;
		}
	} else {
		struct stat64 *arg_stat; /* array of stat structures	*/
		bool_int *valid_stat;	/* which structures are valid	*/

		arg_stat = xmalloc(argc * sizeof (struct stat64));
		valid_stat = xmalloc(argc * sizeof (bool_int));

		/*
		 * Obtain stat64 information for each argument before
		 * constructing the list of mounted file systems. By
		 * touching all these places we force the automounter
		 * to establish any mounts required to access the arguments,
		 * so that the corresponding mount table entries will exist
		 * when we look for them.
		 * It is still possible that the automounter may timeout
		 * mounts between the time we read the mount table and the
		 * time we process the request. Even in that case, when
		 * we issue the statvfs64(2) for the mount point, the file
		 * system will be mounted again. The only problem will
		 * occur if the automounter maps change in the meantime
		 * and the mount point is eliminated.
		 */
		for (i = 0; i < argc; i++)
			valid_stat[i] = (stat64(argv[i], &arg_stat[i]) == 0);

		mtab_read_file();

		for (i = 0; i < argc; i++) {
			char *arg = argv[i];

			dfrp = &requests[request_index];

			dfrp->dfr_index = request_index;
			dfrp->dfr_cmd_arg = arg;

			if (valid_stat[i]) {
				dfrp->dfr_fstype = arg_stat[i].st_fstype;
				if (S_ISBLK(arg_stat[i].st_mode)) {
					bdev_mount_entry(dfrp);
					dfrp->dfr_valid = TRUE;
				} else if (S_ISDIR(arg_stat[i].st_mode) ||
				    S_ISREG(arg_stat[i].st_mode) ||
				    S_ISFIFO(arg_stat[i].st_mode)) {
					path_mount_entry(dfrp,
					    arg_stat[i].st_dev);
					if (! DFR_ISMOUNTEDFS(dfrp)) {
						errors++;
						continue;
					}
					dfrp->dfr_valid = TRUE;
				}
			} else {
				resource_mount_entry(dfrp);
				dfrp->dfr_valid = DFR_ISMOUNTEDFS(dfrp);
			}

			/*
			 * If we haven't managed to verify that the request
			 * is valid, we must have gotten a bad argument.
			 */
			if (!dfrp->dfr_valid) {
				errmsg(ERR_NOFLAGS,
				    "(%-10s) not a block device, directory or "
				    "mounted resource", arg);
				errors++;
				continue;
			}

			/*
			 * Determine the file system type.
			 */
			if (DFR_ISMOUNTEDFS(dfrp))
				dfrp->dfr_fstype =
				    dfrp->dfr_mte->mte_mount->mnt_fstype;
			else
				dfrp->dfr_fstype =
				    find_fstype(dfrp->dfr_cmd_arg);

			request_index++;
		}
	}
	*requests_p = requests;
	*request_count = request_index;
	return (errors);
}


/*
 * Select the appropriate function and flags to use for output.
 * Notice that using both -e and -b options produces a different form of
 * output than either of those two options alone; this is the behavior of
 * the SVR4 df.
 */
static struct df_output *
select_output(void)
{
	static struct df_output dfo;

	/*
	 * The order of checking options follows the option precedence
	 * rules as they are listed in the man page.
	 */
	if (use_scaling) { /* comes from the -h option */
		dfo.dfo_func = k_output;
		dfo.dfo_flags = DFO_HEADER + DFO_STATVFS;
	} else if (V_option) {
		dfo.dfo_func = V_output;
		dfo.dfo_flags = DFO_NOFLAGS;
	} else if (g_option) {
		dfo.dfo_func = g_output;
		dfo.dfo_flags = DFO_STATVFS;
	} else if (k_option || m_option || P_option || v_option) {
		dfo.dfo_func = k_output;
		dfo.dfo_flags = DFO_HEADER + DFO_STATVFS;
	} else if (t_option) {
		dfo.dfo_func = t_output;
		dfo.dfo_flags = DFO_STATVFS;
	} else if (b_option && e_option) {
		dfo.dfo_func = eb_output;
		dfo.dfo_flags = DFO_STATVFS;
	} else if (b_option) {
		dfo.dfo_func = b_output;
		dfo.dfo_flags = DFO_HEADER + DFO_STATVFS;
	} else if (e_option) {
		dfo.dfo_func = e_output;
		dfo.dfo_flags = DFO_HEADER + DFO_STATVFS;
	} else if (n_option) {
		dfo.dfo_func = n_output;
		dfo.dfo_flags = DFO_NOFLAGS;
	} else {
		dfo.dfo_func = default_output;
		dfo.dfo_flags = DFO_STATVFS;
	}
	return (&dfo);
}


/*
 * The (argc,argv) pair contains all the non-option arguments
 */
static void
do_df(int argc, char *argv[])
{
	size_t			i;
	struct df_request	*requests;		/* array of requests */
	size_t			n_requests;
	struct df_request	*dfrp;
	int			errors;

	errors = create_request_list(argc, argv, &requests, &n_requests);

	if (n_requests == 0)
		exit(errors);

	/*
	 * If we are going to run the FSType-specific df command,
	 * rearrange the requests so that we can issue a single command
	 * per file system type.
	 */
	if (o_option) {
		size_t j;

		/*
		 * qsort is not a stable sorting method (i.e. requests of
		 * the same file system type may be swapped, and hence appear
		 * in the output in a different order from the one in which
		 * they were listed in the command line). In order to force
		 * stability, we use the dfr_index field which is unique
		 * for each request.
		 */
		qsort(requests,
		    n_requests, sizeof (struct df_request), df_reqcomp);
		for (i = 0; i < n_requests; i = j) {
			char *fstype = requests[i].dfr_fstype;

			for (j = i+1; j < n_requests; j++)
				if (! EQ(fstype, requests[j].dfr_fstype))
					break;

			/*
			 * At this point, requests in the range [i,j) are
			 * of the same type.
			 *
			 * If the -F option was used, and the user specified
			 * arguments, the filesystem types must match
			 *
			 * XXX: the alternative of doing this check here is to
			 * 	invoke prune_list, but then we have to
			 *	modify this code to ignore invalid requests.
			 */
			if (F_option && ! EQ(fstype, FSType)) {
				size_t k;

				for (k = i; k < j; k++) {
					dfrp = &requests[k];
					if (dfrp->dfr_cmd_arg != NULL) {
						errmsg(ERR_NOFLAGS,
						    "Warning: %s mounted as a "
						    "%s file system",
						    dfrp->dfr_cmd_arg,
						    dfrp->dfr_fstype);
						errors++;
					}
				}
			} else
				errors += run_fs_specific_df(&requests[i], j-i);
		}
	} else {
		size_t valid_requests;

		/*
		 * We have to prune the request list to avoid printing a header
		 * if there are no valid requests
		 */
		errors += prune_list(requests, n_requests, &valid_requests);

		if (valid_requests) {
			struct df_output *dfop = select_output();

			/* indicates if we already printed out a header line */
			int printed_header = 0;

			for (i = 0; i < n_requests; i++) {
				dfrp = &requests[i];
				if (! dfrp->dfr_valid)
					continue;

				/*
				 * If we don't have a mount point,
				 * this must be a block device.
				 */
				if (DFR_ISMOUNTEDFS(dfrp)) {
					struct statvfs64 stvfs;

					if ((dfop->dfo_flags & DFO_STATVFS) &&
					    statvfs64(DFR_MOUNT_POINT(dfrp),
					    &stvfs) == -1) {
						errmsg(ERR_PERROR,
						    "cannot statvfs %s:",
						    DFR_MOUNT_POINT(dfrp));
						errors++;
						continue;
					}
					if ((!printed_header) &&
					    (dfop->dfo_flags & DFO_HEADER)) {
						print_header();
						printed_header = 1;
					}

					(*dfop->dfo_func)(dfrp, &stvfs);
				} else {
					/*
					 *  -h option only works for
					 *  mounted filesystems
					 */
					if (use_scaling) {
						errmsg(ERR_NOFLAGS,
		"-h option incompatible with unmounted special device (%s)",
						    dfrp->dfr_cmd_arg);
						errors++;
						continue;
					}
					errors += run_fs_specific_df(dfrp, 1);
				}
			}
		}
	}
	exit(errors);
}


/*
 * The rest of this file implements the devnm command
 */

static char *
find_dev_name(char *file, dev_t dev)
{
	struct df_request dfreq;

	dfreq.dfr_cmd_arg = file;
	dfreq.dfr_fstype = 0;
	dfreq.dfr_mte = NULL;
	path_mount_entry(&dfreq, dev);
	return (DFR_ISMOUNTEDFS(&dfreq) ? DFR_SPECIAL(&dfreq) : NULL);
}


static void
do_devnm(int argc, char *argv[])
{
	int arg;
	int errors = 0;
	char *dev_name;

	if (argc == 1)
		errmsg(ERR_NONAME, "Usage: %s name ...", DEVNM_CMD);

	mtab_read_file();

	for (arg = 1; arg < argc; arg++) {
		char *file = argv[arg];
		struct stat64 st;

		if (stat64(file, &st) == -1) {
			errmsg(ERR_PERROR, "%s: ", file);
			errors++;
			continue;
		}

		if (! is_remote_fs(st.st_fstype) &&
		    ! EQ(st.st_fstype, MNTTYPE_TMPFS) &&
		    (dev_name = find_dev_name(file, st.st_dev)))
			(void) printf("%s %s\n", dev_name, file);
		else
			errmsg(ERR_NOFLAGS,
			    "%s not found", file);
	}
	exit(errors);
	/* NOTREACHED */
}
