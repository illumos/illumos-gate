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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <mntent.h>
#include <sys/syscall.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include "s5sysmacros.h"
#include "compat.h"

#define	PRINTER_DIR		"/etc/lp/printers/"
#define	PRINTER_CONFIG_FILE	"/configuration"
#define	MNT_LINE_MAX 1024

#define	GETTOK(xx, ll) \
	if ((xx = strtok(ll, sepstr)) == NULL) \
		return (-1); \
	if (strcmp(xx, dash) == 0) \
		xx = NULL

char *mktemp();

static void getPrinterInfo(char *, FILE *);
static char sepstr[] = " \t\n";
static char dash[] = "-";
static int	open_printcap(void);

/* SVR4/SunOS 5.0 equivalent modes */
#define	N_O_NDELAY	0x04
#define	N_O_SYNC	0x10
#define	N_O_NONBLOCK	0x80
#define	N_O_CREAT	0x100
#define	N_O_TRUNC	0x200
#define	N_O_EXCL	0x400

/* Mask corresponding to the bits above in SunOS 4.x */
#define	FLAGS_MASK	(O_SYNC|O_NONBLOCK|O_CREAT|O_TRUNC|O_EXCL \
			|_FNDELAY|_FNBIO)

int
open_com(char *path, int flags, int mode)
{
	int fd, fd2, pathl, inspt, ret = 0;
	int nflags = flags;
	char loc[] = "/lib/locale";
	char *loct = NULL;

	if (flags & FLAGS_MASK) {
		nflags = flags & ~FLAGS_MASK;
		if (flags & O_SYNC)
			nflags |= N_O_SYNC;
		if (flags & (_FNDELAY|O_NONBLOCK)) {
			nflags |= N_O_NONBLOCK;
		}
		if (flags & O_CREAT)
			nflags |= N_O_CREAT;
		if (flags & O_TRUNC)
			nflags |= N_O_TRUNC;
		if (flags & O_EXCL)
			nflags |= N_O_EXCL;
		if (flags & _FNBIO)
			nflags |= N_O_NDELAY;
	}

/* change path from ..../lib/locale/.... to ..../lib/oldlocale/.... XXX */

	if ((loct = (char *)_strstr(path, loc)) != NULL) { /* /lib/locale ?  */
		char locbuf[MAXPATHLEN+100];	  /* to hold new locale path */

		pathl = strlen(path);
		inspt = pathl - strlen(loct) + 5;	/* pos to add "old" */
		(void) strncpy(locbuf, path, inspt); /* copy  path upto lib */
		locbuf[inspt] = '\0';		/* make it a string */
		strcat(locbuf, "old");		/* add "old" */
		strcat(locbuf, loct+5);		/* add remainer of path */
		return (_syscall(SYS_openat, AT_FDCWD, locbuf, nflags, mode));
	}

	if (strcmp(path, "/etc/mtab") == 0)
		return (open_mnt("/etc/mnttab", "mtab", nflags, mode));

	if (strcmp(path, "/etc/fstab") == 0)
		return (open_mnt("/etc/vfstab", "fstab", nflags, mode));

	if (strcmp(path, "/etc/printcap") == 0) {
		if ((fd = _syscall(SYS_openat, AT_FDCWD, path, nflags, mode))
		    >= 0)
			return (fd);
		return (open_printcap());
	}

	if (strcmp(path, "/etc/utmp") == 0 ||
	    strcmp(path, "/var/adm/utmp") == 0) {
		fd = _syscall(SYS_openat,
		    AT_FDCWD, "/var/adm/utmpx", nflags, mode);
		if (fd >= 0)
			fd_add(fd, UTMPX_MAGIC_FLAG);
		return (fd);
	}

	if (strcmp(path, "/var/adm/wtmp") == 0) {
		fd = _syscall(SYS_openat,
		    AT_FDCWD, "/var/adm/wtmpx", nflags, mode);
		if (fd >= 0)
			fd_add(fd, UTMPX_MAGIC_FLAG);
		return (fd);
	}

	return (_syscall(SYS_openat, AT_FDCWD, path, nflags, mode));
}

int
open_mnt(char *fname, char *tname, int flags, int mode)
{
	FILE *fd_in, *fd_out;
	FILE *_fopen();
	char tmp_name[64];
	char line[MNT_LINE_MAX];
	int fd;

	if ((fd_in = _fopen(fname, "r")) == NULL)
		return (-1);

	sprintf(tmp_name, "%s%s%s", "/tmp/", tname, "XXXXXX");
	mktemp(tmp_name);

	if ((fd_out = _fopen(tmp_name, "a+")) == NULL) {
		fclose(fd_in);
		return (-1);
	}

	while (getmntline(line, fd_in) != -1) {
		if (strcmp(fname, "/etc/mnttab") == 0) {
			if (putmline(line, fd_out) == -1) {
				fclose(fd_in);
				fclose(fd_out);
				return (-1);
			}
		} else {	/* processing vfstab */
			if (putfline(line, fd_out) == -1) {
				fclose(fd_in);
				fclose(fd_out);
				return (-1);
			}
		}
	}

	if (feof(fd_in)) {
		fclose(fd_in);
		fclose(fd_out);

		fd = _syscall(SYS_openat, AT_FDCWD, tmp_name, O_RDONLY);

		if (fd == -1 || unlink(tmp_name) == -1)
			return (-1);

		return (fd);
	} else {
		fclose(fd_in);
		fclose(fd_out);
		return (-1);
	}
}

int
getmntline(char *lp, FILE *fp)
{
	int ret;
	char *cp;

	while ((lp = fgets(lp, MNT_LINE_MAX, fp)) != NULL) {
		if (strlen(lp) == MNT_LINE_MAX-1 && lp[MNT_LINE_MAX-2] != '\n')
			return (-1);
		for (cp = lp; *cp == ' ' || *cp == '\t'; cp++)
			;
		if (*cp != '#' && *cp != '\n')
			return (0);
	}
	return (-1);
}

int
putmline(char *line, FILE *fp)
{
	struct mntent mnt;
	char *buf;
	char *devnumstr = 0;	/* the device number, in (hex) ascii */
	char *remainder;	/* remainder of mnt_opts string, after devnum */
	unsigned long devnum;

	GETTOK(mnt.mnt_fsname, line);
	GETTOK(mnt.mnt_dir, NULL);
	GETTOK(mnt.mnt_type, NULL);
	GETTOK(mnt.mnt_opts, NULL);
	GETTOK(buf, NULL);
	mnt.mnt_freq = 0;
	mnt.mnt_passno = 0;

	if (strtok(NULL, sepstr) != NULL)
		return (-1);
	if (strcmp(mnt.mnt_type, "ufs") == 0) {
		mnt.mnt_type = "4.2";
	}

	/*
	 * the device number, if present, follows the '='
	 * in the mnt_opts string.
	 */

	if (mnt.mnt_opts != NULL)
		devnumstr = (char *)strchr(mnt.mnt_opts, '=');

	if (!devnumstr) {
		/* no device number on this line */
		fprintf(fp, "%s %s %s %s %d %d\n",
		    mnt.mnt_fsname, mnt.mnt_dir, mnt.mnt_type,
		    mnt.mnt_opts, mnt.mnt_freq, mnt.mnt_passno);
	} else {
		/* found the device number, convert it to 4.x format */
		devnum = strtol(&devnumstr[1], (char **)NULL, 16);
		remainder = (char *)strchr(&devnumstr[1], ' ');
		devnumstr[1] = 0;	/* null terminate mnt_opts after '=' */
		devnum = cmpdev(devnum);

		fprintf(fp, "%s %s %s %s%4x%s %d %d\n",
		    mnt.mnt_fsname, mnt.mnt_dir, mnt.mnt_type,
		    mnt.mnt_opts, devnum, remainder ? remainder : "",
		    mnt.mnt_freq, mnt.mnt_passno);
	}

	return (0);
}

int
putfline(char *line, FILE *fp)
{
	struct mntent mnt;
	char *buf;

	GETTOK(mnt.mnt_fsname, line);
	GETTOK(buf, NULL);
	GETTOK(mnt.mnt_dir, NULL);
	if (mnt.mnt_dir == NULL && strcmp(mnt.mnt_fsname, "/dev/root") == 0)
		mnt.mnt_dir = "/";
	GETTOK(mnt.mnt_type, NULL);
	GETTOK(buf, NULL);
	GETTOK(buf, NULL);
	GETTOK(mnt.mnt_opts, NULL);
	if (mnt.mnt_opts == NULL)
		mnt.mnt_opts = "rw";
	mnt.mnt_freq = 0;
	mnt.mnt_passno = 0;

	if (strtok(NULL, sepstr) != NULL)
		return (-1);
	if (strcmp(mnt.mnt_type, "ufs") == 0) {
		mnt.mnt_type = "4.2";
	}

	fprintf(fp, "%s %s %s %s %d %d\n",
	    mnt.mnt_fsname, mnt.mnt_dir, mnt.mnt_type,
	    mnt.mnt_opts, mnt.mnt_freq, mnt.mnt_passno);

	return (0);
}

FILE *
_fopen(char *file, char *mode)
{
	extern FILE *_findiop();
	FILE *iop;

	int    plus, oflag, fd;

	iop = _findiop();

	if (iop == NULL || file == NULL || file[0] == '\0')
		return (NULL);
	plus = (mode[1] == '+');
	switch (mode[0]) {
	case 'w':
		oflag = (plus ? O_RDWR : O_WRONLY) | N_O_TRUNC | N_O_CREAT;
		break;
	case 'a':
		oflag = (plus ? O_RDWR : O_WRONLY) | N_O_CREAT;
		break;
	case 'r':
		oflag = plus ? O_RDWR : O_RDONLY;
		break;
	default:
		return (NULL);
	}
	if ((fd = _syscall(SYS_openat, AT_FDCWD, file, oflag, 0666)) < 0)
		return (NULL);
	iop->_cnt = 0;
	iop->_file = fd;
	iop->_flag = plus ? _IORW : (mode[0] == 'r') ? _IOREAD : _IOWRT;
	if (mode[0] == 'a')   {
		if ((lseek(fd, 0L, 2)) < 0)  {
			(void) close(fd);
			return (NULL);
		}
	}
	iop->_base = iop->_ptr = NULL;
	iop->_bufsiz = 0;
	return (iop);
}

static int
open_printcap(void)
{
	FILE		*fd;
	FILE		*_fopen();
	char		tmp_name[] = "/tmp/printcap.XXXXXX";
	int		tmp_file;
	DIR		*printerDir;
	struct dirent	*entry;

	mktemp(tmp_name);
	if ((fd = _fopen(tmp_name, "a+")) == NULL)
		return (-1);
	fprintf(fd, "# Derived from lp(1) configuration information for BCP\n");

	if ((printerDir = opendir(PRINTER_DIR)) != NULL) {
		while ((entry = readdir(printerDir)) != NULL)
			if (entry->d_name[0] != '.')
				getPrinterInfo(entry->d_name, fd);
		closedir(printerDir);
	}
	fclose(fd);

	tmp_file = _syscall(SYS_openat, AT_FDCWD, tmp_name, O_RDONLY);
	if (tmp_file == -1 || unlink(tmp_name) == -1)
		return (-1);

	return (tmp_file);
}

static void
getPrinterInfo(char *printerName, FILE *fd)
{
	char			*fullPath;
	char			*str;
	char			*p;
	char			*c;
	struct stat		buf;
	int			config_fd;

	fullPath = (char *)malloc(strlen(PRINTER_DIR) + strlen(printerName) +
	    strlen(PRINTER_CONFIG_FILE) + 1);
	strcpy(fullPath, PRINTER_DIR);
	strcat(fullPath, printerName);
	strcat(fullPath, PRINTER_CONFIG_FILE);

	if ((config_fd = _syscall(SYS_openat, AT_FDCWD, fullPath, O_RDONLY))
	    == -1) {
		free(fullPath);
		return;
	}
	if ((fstat(config_fd, &buf)) != 0 ||
	    (str = (char *)malloc(buf.st_size + 2)) == NULL) {
		free(fullPath);
		close(config_fd);
		return;
	}
	if ((read(config_fd, str, buf.st_size)) != buf.st_size) {
		free(fullPath);
		free(str);
		close(config_fd);
		return;
	}
	p = &str[buf.st_size];
	p[0] = '\n';
	p[1] = '\0';

	fprintf(fd, "%s:", printerName);
	if ((p = (char *)_strstr(str, "Remote")) != NULL) {
		/* remote printer */
		p = (char *)strchr(p, ' ') + 1;
		c = (char *)strchr(p, '\n');
		*c = '\0';
		fprintf(fd, "lp=:rm=%s:rp=%s:\n", p, printerName);
	} else if ((p = (char *)_strstr(str, "Device")) != NULL) {
		/* local printer */
		p = (char *)strchr(p, ' ') + 1;
		c = (char *)strchr(p, '\n');
		*c = '\0';
		fprintf(fd, "lp=%s:\n", p);
	}
	free(fullPath);
	free(str);
	close(config_fd);
}
