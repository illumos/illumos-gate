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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/fstyp.h>
#include <sys/dkio.h>
#include <sys/param.h>
#include <libfstyp.h>
#include <sys/dktp/fdisk.h>
#include <sys/fs/pc_label.h>

#include "libadm.h"

#define	FSTYP_LIBFS_DIR	"/usr/lib/fs"

static const char *getmodfsname();
static char *getexecpathname();
static void dump_nvlist(nvlist_t *list, int indent);
static boolean_t dos_to_dev(char *path, char **devpath, int *num);
static boolean_t find_dos_drive(int fd, int num, off_t *offset);
static void run_legacy_cmds(int fd, char *device, int vflag);
static int run_cmd(char *path, char *arg0, char *arg1, char *arg2);


static void
usage(void)
{
	(void) fprintf(stderr, gettext("Usage: fstyp [-av] <device>\n"));
	exit(1);
}

int
main(int argc, char **argv)
{
	int		fd = -1;
	int		c;
	int		aflag = 0;
	int		vflag = 0;
	int		indent = 0;
	char		*devpath;
	boolean_t	is_dos;
	int		dos_num;
	off_t		offset = 0;
	nvlist_t	*attr = NULL;
	fstyp_handle_t	h = NULL;
	const char	*modfsname;
	const char	*fsname;
	int		error = FSTYP_ERR_NO_MATCH;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "av")) != -1) {
		switch (c) {
		case 'a':
			aflag = 1;
			break;
		case 'v':
			vflag = 1;
			break;
		default:
			usage();
			break;
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 1) {
		usage();
	}

	modfsname = getmodfsname();

	/*
	 * Open device, find partition offset if requested
	 */
	if (!(is_dos = dos_to_dev(argv[0], &devpath, &dos_num))) {
		devpath = argv[0];
	}
	if ((fd = open(devpath, O_RDONLY)) < 0) {
		error = FSTYP_ERR_DEV_OPEN;
		goto out;
	}
	if (is_dos) {
		if (!find_dos_drive(fd, dos_num, &offset)) {
			error = FSTYP_ERR_NO_PARTITION;
			goto out;
		}
	}

	/*
	 * Use libfstyp to identify filesystem
	 */
	if ((error = fstyp_init(fd, offset, NULL, &h)) != 0) {
		goto out;
	}
	if ((error = fstyp_ident(h, modfsname, &fsname)) != 0) {
		fstyp_fini(h);
		h = NULL;

		run_legacy_cmds(fd, argv[0], vflag);

		goto out;
	}

	(void) printf("%s\n", fsname);

	/*
	 * Output additional info if requested
	 */
	if (vflag) {
		error = fstyp_dump(h, stdout, stderr);
	}
	if (aflag || (vflag && (error == FSTYP_ERR_NOP))) {
		if ((error = fstyp_get_attr(h, &attr)) != 0) {
			goto out;
		}
		dump_nvlist(attr, indent);
	}

out:
	if (error != 0) {
		(void) fprintf(stderr, gettext("unknown_fstyp (%s)\n"),
		    fstyp_strerror(h, error));
	}
	if (h != NULL) {
		fstyp_fini(h);
	}
	if (fd >= 0) {
		(void) close(fd);
	}
	if (devpath != argv[0]) {
		free(devpath);
	}
	return (error);

}

#define	NVP(elem, type, vtype, ptype, format) { \
	vtype	value; \
\
	(void) nvpair_value_##type(elem, &value); \
	(void) printf("%*s%s: " format "\n", indent, "", \
	    nvpair_name(elem), (ptype)value); \
}

#define	NVPA(elem, type, vtype, ptype, format) { \
	uint_t	i, count; \
	vtype	*value;  \
\
	(void) nvpair_value_##type(elem, &value, &count); \
	for (i = 0; i < count; i++) { \
		(void) printf("%*s%s[%d]: " format "\n", indent, "", \
		    nvpair_name(elem), i, (ptype)value[i]); \
	} \
}

static void
dump_nvlist(nvlist_t *list, int indent)
{
	nvpair_t	*elem = NULL;
	boolean_t	bool_value;
	nvlist_t	*nvlist_value;
	nvlist_t	**nvlist_array_value;
	uint_t		i, count;

	if (list == NULL) {
		return;
	}

	while ((elem = nvlist_next_nvpair(list, elem)) != NULL) {
		switch (nvpair_type(elem)) {
		case DATA_TYPE_BOOLEAN_VALUE:
			(void) nvpair_value_boolean_value(elem, &bool_value);
			(void) printf("%*s%s: %s\n", indent, "",
			    nvpair_name(elem), bool_value ? "true" : "false");
			break;

		case DATA_TYPE_BYTE:
			NVP(elem, byte, uchar_t, int, "%u");
			break;

		case DATA_TYPE_INT8:
			NVP(elem, int8, int8_t, int, "%d");
			break;

		case DATA_TYPE_UINT8:
			NVP(elem, uint8, uint8_t, int, "%u");
			break;

		case DATA_TYPE_INT16:
			NVP(elem, int16, int16_t, int, "%d");
			break;

		case DATA_TYPE_UINT16:
			NVP(elem, uint16, uint16_t, int, "%u");
			break;

		case DATA_TYPE_INT32:
			NVP(elem, int32, int32_t, long, "%ld");
			break;

		case DATA_TYPE_UINT32:
			NVP(elem, uint32, uint32_t, ulong_t, "%lu");
			break;

		case DATA_TYPE_INT64:
			NVP(elem, int64, int64_t, longlong_t, "%lld");
			break;

		case DATA_TYPE_UINT64:
			NVP(elem, uint64, uint64_t, u_longlong_t, "%llu");
			break;

		case DATA_TYPE_STRING:
			NVP(elem, string, char *, char *, "'%s'");
			break;

		case DATA_TYPE_BYTE_ARRAY:
			NVPA(elem, byte_array, uchar_t, int, "%u");
			break;

		case DATA_TYPE_INT8_ARRAY:
			NVPA(elem, int8_array, int8_t, int, "%d");
			break;

		case DATA_TYPE_UINT8_ARRAY:
			NVPA(elem, uint8_array, uint8_t, int, "%u");
			break;

		case DATA_TYPE_INT16_ARRAY:
			NVPA(elem, int16_array, int16_t, int, "%d");
			break;

		case DATA_TYPE_UINT16_ARRAY:
			NVPA(elem, uint16_array, uint16_t, int, "%u");
			break;

		case DATA_TYPE_INT32_ARRAY:
			NVPA(elem, int32_array, int32_t, long, "%ld");
			break;

		case DATA_TYPE_UINT32_ARRAY:
			NVPA(elem, uint32_array, uint32_t, ulong_t, "%lu");
			break;

		case DATA_TYPE_INT64_ARRAY:
			NVPA(elem, int64_array, int64_t, longlong_t, "%lld");
			break;

		case DATA_TYPE_UINT64_ARRAY:
			NVPA(elem, uint64_array, uint64_t, u_longlong_t,
			    "%llu");
			break;

		case DATA_TYPE_STRING_ARRAY:
			NVPA(elem, string_array, char *, char *, "'%s'");
			break;

		case DATA_TYPE_NVLIST:
			(void) nvpair_value_nvlist(elem, &nvlist_value);
			(void) printf("%*s%s:\n", indent, "",
			    nvpair_name(elem));
			dump_nvlist(nvlist_value, indent + 4);
			break;

		case DATA_TYPE_NVLIST_ARRAY:
			(void) nvpair_value_nvlist_array(elem,
			    &nvlist_array_value, &count);
			for (i = 0; i < count; i++) {
				(void) printf("%*s%s[%u]:\n", indent, "",
				    nvpair_name(elem), i);
				dump_nvlist(nvlist_array_value[i], indent + 4);
			}
			break;

		default:
			(void) printf(gettext("bad config type %d for %s\n"),
			    nvpair_type(elem), nvpair_name(elem));
		}
	}
}

/*
 * If the executable is a fs-specific hardlink, /usr/lib/fs/<fsname>/fstyp,
 * return that fsname; otherwise return NULL.
 */
static const char *
getmodfsname()
{
	static char fsname_buf[FSTYPSZ + 1];
	char	*fsname = NULL;
	char	*path;
	char	*p;
	int	len;

	if ((path = getexecpathname()) == NULL) {
		return (NULL);
	}
	if ((p = strrchr(path, '/')) != NULL) {
		*p = '\0';
		if ((p = strrchr(path, '/')) != NULL) {
			*p++ = '\0';
			len = strlen(p);
			if ((strcmp(path, FSTYP_LIBFS_DIR) == 0) &&
			    (len > 0) && (len < sizeof (fsname_buf))) {
				(void) strlcpy(fsname_buf, p,
				    sizeof (fsname_buf));
				fsname = fsname_buf;
			}
		}
	}
	free(path);
	return (fsname);
}

/*
 * Return executable's absolute pathname
 */
static char *
getexecpathname()
{
	size_t		size;
	const char	*execname;
	char		*cwd;
	char		*path;
	char		*rpath;

	size = pathconf(".", _PC_PATH_MAX) + 1;
	path = malloc(size);
	rpath = malloc(size);
	cwd = getcwd(NULL, size);
	if ((path == NULL) || (rpath == NULL) || (cwd == NULL)) {
		goto out;
	}
	execname = getexecname();

	if (execname[0] == '/') {
		(void) snprintf(path, size, "%s", execname);
	} else {
		(void) snprintf(path, size, "%s/%s", cwd, execname);
	}
	if (realpath(path, rpath) == NULL) {
		free(rpath);
		rpath = NULL;
	}

out:
	if (path != NULL) {
		free(path);
	}
	if (cwd != NULL) {
		free(cwd);
	}
	return (rpath);
}

/*
 * Separates dos notation device spec into device and drive number
 */
static boolean_t
dos_to_dev(char *path, char **devpath, int *num)
{
	char *p;

	if ((p = strrchr(path, ':')) == NULL) {
		return (B_FALSE);
	}
	if ((*num = atoi(p + 1)) == 0) {
		return (B_FALSE);
	}
	p[0] = '\0';
	*devpath = getfullrawname(path);
	p[0] = ':';
	if (*devpath != NULL && **devpath == '\0') {
		free(*devpath);
		*devpath = NULL;
	}
	return (*devpath != NULL);
}

static boolean_t
is_dos_drive(uchar_t type)
{
	return ((type == DOSOS12) || (type == DOSOS16) ||
	    (type == DOSHUGE) || (type == FDISK_WINDOWS) ||
	    (type == FDISK_EXT_WIN) || (type == FDISK_FAT95) ||
	    (type == DIAGPART));
}

static boolean_t
is_dos_extended(uchar_t id)
{
	return ((id == EXTDOS) || (id == FDISK_EXTLBA));
}

struct part_find_s {
	int	num;
	int	count;
	int	systid;
	int	r_systid;
	uint32_t	r_relsect;
	uint32_t	r_numsect;
};

enum { WALK_CONTINUE, WALK_TERMINATE };

/*
 * Walk partition tables and invoke a callback for each.
 */
static void
walk_partitions(int fd, uint32_t startsec, off_t secsz,
    int (*f)(void *, int, uint32_t, uint32_t), void *arg)
{
	uint32_t buf[1024/4];
	int bufsize = 1024;
	struct mboot *mboot = (struct mboot *)&buf[0];
	struct ipart ipart[FD_NUMPART];
	uint32_t sec = startsec;
	uint32_t lastsec = sec + 1;
	uint32_t relsect;
	int ext = 0;
	int systid;
	boolean_t valid;
	int i;

	while (sec != lastsec) {
		if (pread(fd, buf, bufsize, (off_t)sec * secsz) != bufsize) {
			break;
		}
		lastsec = sec;
		if (ltohs(mboot->signature) != MBB_MAGIC) {
			break;
		}
		bcopy(mboot->parts, ipart, FD_NUMPART * sizeof (struct ipart));

		for (i = 0; i < FD_NUMPART; i++) {
			systid = ipart[i].systid;
			relsect = sec + ltohi(ipart[i].relsect);
			if (systid == 0) {
				continue;
			}
			valid = B_TRUE;
			if (is_dos_extended(systid) && (sec == lastsec)) {
				sec = startsec + ltohi(ipart[i].relsect);
				if (ext++ == 0) {
					relsect = startsec = sec;
				} else {
					valid = B_FALSE;
				}
			}
			if (valid && f(arg, ipart[i].systid, relsect,
			    ltohi(ipart[i].numsect)) == WALK_TERMINATE) {
				return;
			}
		}
	}
}

static int
find_dos_drive_cb(void *arg, int systid, uint32_t relsect, uint32_t numsect)
{
	struct part_find_s *p = arg;

	if (is_dos_drive(systid)) {
		if (++p->count == p->num) {
			p->r_relsect = relsect;
			p->r_numsect = numsect;
			p->r_systid = systid;
			return (WALK_TERMINATE);
		}
	}

	return (WALK_CONTINUE);
}

/*
 * Given a dos drive number, return its relative offset in the drive.
 */
static boolean_t
find_dos_drive(int fd, int num, off_t *offset)
{
	struct dk_minfo mi;
	off_t secsz;
	struct part_find_s p = { 0, 0, 0, 0, 0, 0 };

	p.num = num;

	/*
	 * It is possible that the media we are dealing with can have different
	 * sector size than the default 512 bytes. Query the driver and check
	 * whether the media has different sector size.
	 */
	if (ioctl(fd, DKIOCGMEDIAINFO, &mi) < 0)
		secsz = DEV_BSIZE;
	else
		secsz = mi.dki_lbsize;

	if (num > 0) {
		walk_partitions(fd, 0, secsz, find_dos_drive_cb, &p);
		if (p.count == num) {
			*offset = secsz * (off_t)p.r_relsect;
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * libfstyp identification failed: as a last resort, try to
 * find and run legacy /usr/lib/fs/<fsname>/fstyp commands.
 */
static void
run_legacy_cmds(int fd, char *device, int vflag)
{
	char		*lib_dir = FSTYP_LIBFS_DIR;
	char		*path;
	long		name_max;
	DIR		*dirp;
	struct dirent	*dp_mem, *dp;
	struct stat	st;
	fstyp_handle_t	h;
	int		error;
	char		*arg1, *arg2;

	if (vflag) {
		arg1 = "-v";
		arg2 = device;
	} else {
		arg1 = device;
		arg2 = NULL;
	}

	if ((dirp = opendir(lib_dir)) == NULL) {
		return;
	}

	name_max = pathconf(lib_dir, _PC_NAME_MAX);
	path = calloc(1, name_max + 1);
	dp = dp_mem = calloc(1, sizeof (struct dirent) + name_max + 1);
	if ((path == NULL) || (dp_mem == NULL)) {
		goto out;
	}

	while ((readdir_r(dirp, dp, &dp) == 0) && (dp != NULL)) {
		if (dp->d_name[0] == '.') {
			continue;
		}
		(void) snprintf(path, name_max, "%s/%s", lib_dir, dp->d_name);

		/* it's legacy if there's no libfstyp module for it */
		error = fstyp_init(fd, 0, path, &h);
		if (error != FSTYP_ERR_MOD_NOT_FOUND) {
			if (error == 0) {
				fstyp_fini(h);
			}
			continue;
		}

		/* file must exist and be executable */
		(void) snprintf(path, name_max,
		    "%s/%s/fstyp", lib_dir, dp->d_name);
		if ((stat(path, &st) < 0) ||
		    ((st.st_mode & S_IXUSR) == 0)) {
			continue;
		}

		if ((error = run_cmd(path, "fstyp", arg1, arg2)) == 0) {
			exit(0);
		}
	}

out:
	if (dp_mem != NULL) {
		free(dp_mem);
	}
	if (path != NULL) {
		free(path);
	}
	(void) closedir(dirp);
}

static int
run_cmd(char *path, char *arg0, char *arg1, char *arg2)
{
	pid_t	pid;
	int	status = 1;

	pid = fork();
	if (pid < 0) {
		return (1);
	} else if (pid == 0) {
		/* child */
		(void) execl(path, arg0, arg1, arg2, 0);
		exit(1);
	}
	/* parent */
	(void) wait(&status);
	return (status);
}
