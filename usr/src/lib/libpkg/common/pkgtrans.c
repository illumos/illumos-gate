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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <dirent.h>
#include <signal.h>
#include <devmgmt.h>
#include <note.h>
#include "pkginfo.h"
#include "pkgstrct.h"
#include "pkgtrans.h"
#include "pkgdev.h"
#include "pkglib.h"
#include "pkglibmsgs.h"
#include "pkglocale.h"

extern char	*pkgdir; 		/* pkgparam.c */

/* libadm.a */
extern char	*devattr(char *device, char *attribute);
extern char	*fpkginst(char *pkg, ...);
extern int	fpkginfo(struct pkginfo *info, char *pkginst);
extern int	getvol(char *device, char *label, int options, char *prompt);
extern int	_getvol(char *device, char *label, int options, char *prompt,
			char *norewind);

/* dstream.c */
extern int	ds_ginit(char *device);
extern int	ds_close(int pkgendflg);

#define	CPIOPROC	"/usr/bin/cpio"

#define	CMDSIZE	512	/* command block size */

#define	BLK_SIZE	512		/* size of logical block */

#define	ENTRY_MAX	256 /* max size of entry for cpio cmd or header */

#define	PKGINFO	"pkginfo"
#define	PKGMAP	"pkgmap"
#define	MAP_STAT_SIZE	60	/* 1st line of pkgmap (3 numbers & a : */

#define	INSTALL	"install"
#define	RELOC	"reloc"
#define	ROOT	"root"
#define	ARCHIVE	"archive"

static struct	pkgdev srcdev, dstdev;
static char	*tmpdir;
static char	*tmppath;
static char	*tmpsymdir = NULL;
static char	dstinst[NON_ABI_NAMELNGTH];
static char 	*ids_name, *ods_name;
static int	ds_volcnt;
static int	ds_volno;
static int	compressedsize, has_comp_size;

static void	(*sigintHandler)();
static void	(*sighupHandler)();
static void	cleanup(void);
static void	sigtrap(int signo);
static int	rd_map_size(FILE *fp, int *npts, int *maxpsz, int *cmpsize);

static int	cat_and_count(struct dm_buf *, char *);

static int	ckoverwrite(char *dir, char *inst, int options);
static int	pkgxfer(char *srcinst, int options);
static int	wdsheader(struct dm_buf *, char *device, char **pkg);
static struct dm_buf	*genheader(char *, char **);

extern int	ds_fd;	/* open file descriptor for data stream WHERE? */

static char *root_names[] = {
	"root",
	"root.cpio",
	"root.Z",
	"root.cpio.Z",
	0
};

static char *reloc_names[] = {
	"reloc",
	"reloc.cpio",
	"reloc.Z",
	"reloc.cpio.Z",
	0
};

static int	signal_received = 0;

char	**xpkg; 	/* array of transferred packages */
int	nxpkg;

static	char *allpkg[] = {
	"all",
	NULL
};

static struct dm_buf hdrbuf;
static char *pinput, *nextpinput;

int
pkghead(char *device)
{
	char	*pt;
	int	n;

	cleanup();


	if (device == NULL)
		return (0);
	else if ((device[0] == '/') && !isdir(device)) {
		pkgdir = device;
		return (0);
	} else if ((pt = devattr(device, "pathname")) != NULL && !isdir(pt)) {
		pkgdir = pt;
		return (0);
	}

	/* check for datastream */
	if (n = pkgtrans(device, (char *)0, allpkg, PT_SILENT|PT_INFO_ONLY)) {
		cleanup();
		return (n);
	}
		/* pkgtrans has set pkgdir */
	return (0);
}

static char *
mgets(char *buf, int size)
{
	nextpinput = strchr(pinput, '\n');
	if (nextpinput == NULL)
		return (0);
	*nextpinput = '\0';
	if ((int)strlen(pinput) > size)
		return (0);
	(void) strncpy(buf, pinput, strlen(pinput));
	buf[strlen(pinput)] = '\0';
	pinput = nextpinput + 1;
	return (buf);
}
/*
 * Here we construct the package size summaries for the headers. The
 * pkgmap file associated with fp must be rewound to the beginning of the
 * file. Note that we read three values from pkgmap first line in order
 * to get the *actual* size if this package is compressed.
 * This returns
 *	0 : error
 *	2 : not a compressed package
 *	3 : compressed package
 * and sets has_comp_size to indicate whether or not this is a compressed
 * package.
 */
static int
rd_map_size(FILE *fp, int *npts, int *maxpsz, int *cmpsize)
{
	int n;
	char line_buffer[MAP_STAT_SIZE];

	/* First read the null terminated first line */
	if (fgets(line_buffer, MAP_STAT_SIZE, fp) == NULL) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_NOSIZE));
		(void) fclose(fp);
		ecleanup();
		return (0);
	}

	n = sscanf(line_buffer, ": %d %d %d", npts, maxpsz, cmpsize);

	if (n == 3)		/* A valid compressed package entry */
		has_comp_size = 1;
	else if (n == 2)	/* A valid standard package entry */
		has_comp_size = 0;
	else {			/* invalid entry */
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_NOSIZE));
		(void) fclose(fp);
		ecleanup();
		return (0);
	}

	return (n);
}

/* will return 0, 1, 3, or 99 */
static int
_pkgtrans(char *device1, char *device2, char **pkg, int options)
{
	char			*src, *dst;
	int			errflg, i, n;
	struct			dm_buf *hdr;

	if (signal_received > 0) {
		return (1);
	}

	/* transfer spool to appropriate device */
	if (devtype(device1, &srcdev)) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_BADDEV), device1);
		return (1);
	}
	srcdev.rdonly++;

	/* check for datastream */
	ids_name = NULL;
	if (srcdev.bdevice) {
		if (n = _getvol(srcdev.bdevice, NULL, NULL,
		    pkg_gt("Insert %v into %p."), srcdev.norewind)) {
			cleanup();
			if (n == 3)
				return (3);
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_GETVOL));
			return (1);
		}
		if (ds_readbuf(srcdev.cdevice))
			ids_name = srcdev.cdevice;
	}

	if (srcdev.cdevice && !srcdev.bdevice)
		ids_name = srcdev.cdevice;
	else if (srcdev.pathname) {
		ids_name = srcdev.pathname;
		if (access(ids_name, 0) == -1) {
			progerr(ERR_TRANSFER);
			logerr(pkg_gt(MSG_GETVOL));
			return (1);
		}
	}

	if (!ids_name && device2 == (char *)0) {
		if (n = pkgmount(&srcdev, NULL, 1, 0, 0)) {
			cleanup();
			return (n);
		}
		if (srcdev.mount && *srcdev.mount)
			pkgdir = strdup(srcdev.mount);
		return (0);
	}

	if (ids_name && device2 == (char *)0) {
		tmppath = tmpnam(NULL);
		tmppath = strdup(tmppath);
		if (tmppath == NULL) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_MEM));
			return (1);
		}
		if (mkdir(tmppath, 0755)) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_MKDIR), tmppath);
			return (1);
		}
		device2 = tmppath;
	}

	if (devtype(device2, &dstdev)) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_BADDEV), device2);
		return (1);
	}

	if ((srcdev.cdevice && dstdev.cdevice) &&
	    strcmp(srcdev.cdevice, dstdev.cdevice) == 0) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_SAMEDEV));
		return (1);
	}

	ods_name = NULL;
	if (dstdev.cdevice && !dstdev.bdevice || dstdev.pathname)
		options |= PT_ODTSTREAM;

	if (options & PT_ODTSTREAM) {
		if (!((ods_name = dstdev.cdevice) != NULL ||
		    (ods_name = dstdev.pathname) != NULL)) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_BADDEV), device2);
			return (1);
		}
		if (ids_name) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_TWODSTREAM));
			return (1);
		}
	}

	if ((srcdev.dirname && dstdev.dirname) &&
	    strcmp(srcdev.dirname, dstdev.dirname) == 0) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_SAMEDEV));
		return (1);
	}

	if ((srcdev.pathname && dstdev.pathname) &&
	    strcmp(srcdev.pathname, dstdev.pathname) == 0) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_SAMEDEV));
		return (1);
	}

	if (signal_received > 0) {
		return (1);
	}

	if (ids_name) {
		if (srcdev.cdevice && !srcdev.bdevice &&
		(n = _getvol(srcdev.cdevice, NULL, NULL, NULL,
		    srcdev.norewind))) {
			cleanup();
			if (n == 3)
				return (3);
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_GETVOL));
			return (1);
		}
		if (srcdev.dirname = tmpnam(NULL))
			tmpdir = srcdev.dirname = strdup(srcdev.dirname);

		if ((srcdev.dirname == NULL) || mkdir(srcdev.dirname, 0755) ||
		    chdir(srcdev.dirname)) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_NOTEMP), srcdev.dirname);
			cleanup();
			return (1);
		}
		if (ds_init(ids_name, pkg, srcdev.norewind)) {
			cleanup();
			return (1);
		}
	} else if (srcdev.mount) {
		if (n = pkgmount(&srcdev, NULL, 1, 0, 0)) {
			cleanup();
			return (n);
		}
	}

	src = srcdev.dirname;
	dst = dstdev.dirname;

	if (chdir(src)) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_CHDIR), src);
		cleanup();
		return (1);
	}

	if (signal_received > 0) {
		return (1);
	}

	xpkg = pkg = gpkglist(src, pkg, NULL);
	if (!pkg) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_NOPKGS), src);
		cleanup();
		return (1);
	}

	for (nxpkg = 0; pkg[nxpkg]; /* void */) {
		nxpkg++; /* count */
	}

	if (ids_name) {
		ds_order(pkg); /* order requests */
	}

	if (signal_received > 0) {
		return (1);
	}

	if (options & PT_ODTSTREAM) {
		char line[128];

		if (!dstdev.pathname &&
		    (n = _getvol(ods_name, NULL, DM_FORMAT, NULL,
		    dstdev.norewind))) {
			cleanup();
			if (n == 3)
				return (3);
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_GETVOL));
			return (1);
		}
		if ((hdr = genheader(src, pkg)) == NULL) {
			cleanup();
			return (1);
		}

		/* write out header to stream */
		if (wdsheader(hdr, ods_name, pkg)) {
			cleanup();
			return (1);
		}

		ds_volno = 1; /* number of volumes in datastream */
		pinput = hdrbuf.text_buffer;
		/* skip past first line in header */
		(void) mgets(line, 128);
	}

	if (signal_received > 0) {
		return (1);
	}

	errflg = 0;

	for (i = 0; pkg[i]; i++) {

		if (signal_received > 0) {
			return (1);
		}

		if (!(options & PT_ODTSTREAM) && dstdev.mount) {
			if (n = pkgmount(&dstdev, NULL, 0, 0, 1)) {
				cleanup();
				return (n);
			}
		}
		if (errflg = pkgxfer(pkg[i], options)) {
			pkg[i] = NULL;
			if ((options & PT_ODTSTREAM) || (errflg != 2))
				break;
		} else if (strcmp(dstinst, pkg[i]))
			pkg[i] = strdup(dstinst);
	}

	if (!(options & PT_ODTSTREAM) && dst) {
		pkgdir = strdup(dst);
	}

	/*
	 * No cleanup of temporary directories created in this
	 * function is done here. The calling function must do
	 * the cleanup.
	 */

	return (signal_received > 0 ? 1 : errflg);
}

int
pkgtrans(char *device1, char *device2, char **pkg, int options)
{
	int			r;
	struct sigaction	nact;
	struct sigaction	oact;

	/*
	 * setup signal handlers for SIGINT and SIGHUP and release hold
	 */

	/* hold SIGINT/SIGHUP interrupts */

	(void) sighold(SIGHUP);
	(void) sighold(SIGINT);

	/* hook SIGINT to sigtrap */

	nact.sa_handler = sigtrap;
	nact.sa_flags = SA_RESTART;
	(void) sigemptyset(&nact.sa_mask);

	if (sigaction(SIGINT, &nact, &oact) < 0) {
		sigintHandler = SIG_DFL;
	} else {
		sigintHandler = oact.sa_handler;
	}

	/* hook SIGHUP to sigtrap */

	nact.sa_handler = sigtrap;
	nact.sa_flags = SA_RESTART;
	(void) sigemptyset(&nact.sa_mask);

	if (sigaction(SIGHUP, &nact, &oact) < 0) {
		sighupHandler = SIG_DFL;
	} else {
		sighupHandler = oact.sa_handler;
	}

	/* reset signal received count */

	signal_received = 0;

	/* release hold on signals */

	(void) sigrelse(SIGHUP);
	(void) sigrelse(SIGINT);

	/*
	 * perform the package translation
	 */

	r = _pkgtrans(device1, device2, pkg, options);

	/*
	 * reset signal handlers
	 */

	/* hold SIGINT/SIGHUP interrupts */

	(void) sighold(SIGHUP);
	(void) sighold(SIGINT);

	/* reset SIGINT */

	nact.sa_handler = sigintHandler;
	nact.sa_flags = SA_RESTART;
	(void) sigemptyset(&nact.sa_mask);

	(void) sigaction(SIGINT, &nact, (struct sigaction *)NULL);

	/* reset SIGHUP */

	nact.sa_handler = sighupHandler;
	nact.sa_flags = SA_RESTART;
	(void) sigemptyset(&nact.sa_mask);

	(void) sigaction(SIGHUP, &nact, (struct sigaction *)NULL);

	/* if signal received and pkgtrans returned error, call cleanup */

	if (signal_received > 0) {
		if (r != 0) {
			cleanup();
		}
		(void) kill(getpid(), SIGINT);
	}

	/* release hold on signals */

	(void) sigrelse(SIGHUP);
	(void) sigrelse(SIGINT);

	return (r);
}

/*
 * This function concatenates append to the text described in the buf_ctrl
 * structure. This code modifies data in this structure and handles all
 * allocation issues. It returns '0' if everything was successful and '1'
 * if not.
 */
static int
cat_and_count(struct dm_buf *buf_ctrl, char *append)
{

	/* keep allocating until we have enough room to hold string */
	while ((buf_ctrl->offset + (int)strlen(append))
	    >= buf_ctrl->allocation) {
		/* reallocate (and maybe move) text buffer */
		if ((buf_ctrl->text_buffer =
		    (char *)realloc(buf_ctrl->text_buffer,
		    buf_ctrl->allocation + BLK_SIZE)) == NULL) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_MEM));
			free(buf_ctrl->text_buffer);
			return (1);
		}

		/* clear the new memory */
		(void) memset(buf_ctrl->text_buffer +
		    buf_ctrl->allocation, '\0', BLK_SIZE);

		/* adjust total allocation */
		buf_ctrl->allocation += BLK_SIZE;
	}

	/* append new string to end of buffer */
	while (*append) {
		*(buf_ctrl->text_buffer + buf_ctrl->offset) = *append++;
		(buf_ctrl->offset)++;
	}

	return (0);
}

static struct dm_buf *
genheader(char *src, char **pkg)
{

	FILE	*fp;
	char	path[MAXPATHLEN], tmp_entry[ENTRY_MAX];
	int	i, n, nparts, maxpsize;
	int	partcnt;
	long	totsize;
	struct stat statbuf;

	if ((hdrbuf.text_buffer = (char *)malloc(BLK_SIZE)) == NULL) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_MEM));
		return (NULL);
	}

	/* clear the new memory */
	(void) memset(hdrbuf.text_buffer, '\0', BLK_SIZE);

	/* set up the buffer control structure for the header */
	hdrbuf.offset = 0;
	hdrbuf.allocation = BLK_SIZE;

	(void) cat_and_count(&hdrbuf, HDR_PREFIX);
	(void) cat_and_count(&hdrbuf, "\n");

	nparts = maxpsize = 0;

	totsize = 0;
	for (i = 0; pkg[i]; i++)  {
		(void) snprintf(path, MAXPATHLEN, "%s/%s/%s",
		    src, pkg[i], PKGINFO);
		if (stat(path, &statbuf) < 0) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_BADPKGINFO));
			ecleanup();
			return (NULL);
		}
		totsize += statbuf.st_size/BLK_SIZE + 1;
	}

	/*
	 * totsize contains number of blocks used by the pkginfo files
	 */
	totsize += i/4 + 1;
	if (dstdev.capacity && totsize > dstdev.capacity) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_NOSPACE), totsize, dstdev.capacity);
		ecleanup();
		return (NULL);
	}

	ds_volcnt = 1;
	for (i = 0; pkg[i]; i++) {
		partcnt = 0;
		(void) snprintf(path, MAXPATHLEN, "%s/%s/%s",
		    src, pkg[i], PKGMAP);
		if ((fp = fopen(path, "r")) == NULL) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_NOPKGMAP), pkg[i]);
			ecleanup();
			return (NULL);
		}

		/* Evaluate the first entry in pkgmap */
		n = rd_map_size(fp, &nparts, &maxpsize, &compressedsize);

		if (n == 3)	/* It's a compressed package */
			/* The header needs the *real* size */
			maxpsize = compressedsize;
		else if (n == 0)	/* pkgmap is corrupt */
			return (NULL);

		if (dstdev.capacity && maxpsize > dstdev.capacity) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_NOSPACE), (long)maxpsize,
			    dstdev.capacity);
			(void) fclose(fp);
			ecleanup();
			return (NULL);
		}

		/* add pkg name, number of parts and the max part size */
		if (snprintf(tmp_entry, ENTRY_MAX, "%s %d %d",
				pkg[i], nparts, maxpsize) >= ENTRY_MAX) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(ERR_MEM));
			(void) fclose(fp);
			ecleanup();
			return (NULL);
		}
		if (cat_and_count(&hdrbuf, tmp_entry)) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_MEM));
			(void) fclose(fp);
			ecleanup();
			return (NULL);
		}

		totsize += nparts * maxpsize;
		if (dstdev.capacity && dstdev.capacity < totsize) {
			int lastpartcnt = 0;

			if (totsize)
				totsize -= nparts * maxpsize;
			while (partcnt < nparts) {
				while (totsize <= dstdev.capacity &&
				    partcnt <= nparts) {
					totsize +=  maxpsize;
					partcnt++;
				}
				/* partcnt == 0 means skip to next volume */
				if (partcnt)
					partcnt--;
				(void) snprintf(tmp_entry, ENTRY_MAX,
				    " %d", partcnt - lastpartcnt);
				if (cat_and_count(&hdrbuf, tmp_entry)) {
					progerr(pkg_gt(ERR_TRANSFER));
					logerr(pkg_gt(MSG_MEM));
					(void) fclose(fp);
					ecleanup();
					return (NULL);
				}
				ds_volcnt++;
				totsize = 0;
				lastpartcnt = partcnt;
			}
			/* first parts/volume number does not count */
			ds_volcnt--;
		}

		if (cat_and_count(&hdrbuf, "\n")) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_MEM));
			(void) fclose(fp);
			ecleanup();
			return (NULL);
		}

		(void) fclose(fp);
	}

	if (cat_and_count(&hdrbuf, HDR_SUFFIX) ||
	    cat_and_count(&hdrbuf, "\n")) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_MEM));
		(void) fclose(fp);
		ecleanup();
		return (NULL);
	}
	return (&hdrbuf);
}

static int
wdsheader(struct dm_buf *hdr, char *device, char **pkg)
{
	char	tmp_entry[ENTRY_MAX], tmp_file[L_tmpnam+1];
	int	i, n;
	int	list_fd;
	int	block_cnt;

	(void) ds_close(0);
	if (dstdev.pathname)
		ds_fd = creat(device, 0644);
	else
		ds_fd = open(device, 1);

	if (ds_fd < 0) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_OPEN), device, errno);
		return (1);
	}

	if (ds_ginit(device) < 0) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_OPEN), device, errno);
		(void) ds_close(0);
		return (1);
	}

	/*
	 * The loop below assures compatibility with tapes that don't
	 * have a block size (e.g.: Exabyte) by forcing EOR at the end
	 * of each 512 bytes.
	 */
	for (block_cnt = 0; block_cnt < hdr->allocation;
		block_cnt += BLK_SIZE) {
		(void) write(ds_fd, (hdr->text_buffer + block_cnt), BLK_SIZE);
	}

	/*
	 * write the first cpio() archive to the datastream
	 * which should contain the pkginfo & pkgmap files
	 * for all packages
	 */
	(void) tmpnam(tmp_file);	/* temporary file name */
	if ((list_fd = open(tmp_file, O_RDWR | O_CREAT, 0644)) == -1) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_NOTMPFIL), tmp_file);
		return (1);
	}

	/*
	 * Create a cpio-compatible list of the requisite files in
	 * the temporary file.
	 */
	for (i = 0; pkg[i]; i++) {
		register ssize_t entry_size;

		/*
		 * Copy pkginfo and pkgmap filenames into the
		 * temporary string allowing for the first line
		 * as a special case.
		 */
		entry_size = sprintf(tmp_entry,
		    (i == 0) ? "%s/%s\n%s/%s" : "\n%s/%s\n%s/%s",
		    pkg[i], PKGINFO, pkg[i], PKGMAP);

		if (write(list_fd, tmp_entry,
		    entry_size) != entry_size) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_NOTMPFIL), tmp_file);
			(void) close(list_fd);
			ecleanup();
			return (1);
		}
	}

	(void) lseek(list_fd, 0, SEEK_SET);

	(void) snprintf(tmp_entry, sizeof (tmp_entry),
	    "%s -ocD -C %d", CPIOPROC, (int)BLK_SIZE);

	if (n = esystem(tmp_entry, list_fd, ds_fd)) {
		rpterr();
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_CMDFAIL), tmp_entry, n);
		(void) close(list_fd);
		(void) unlink(tmp_file);
		cleanup();
		return (1);
	}

	(void) close(list_fd);
	(void) unlink(tmp_file);

	return (0);
}

static int
ckoverwrite(char *dir, char *inst, int options)
{
	char	path[PATH_MAX];

	(void) snprintf(path, sizeof (path), "%s/%s", dir, inst);
	if (access(path, 0) == 0) {
		if (options & PT_OVERWRITE)
			return (rrmdir(path));
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_EXISTS), path);
		return (1);
	}
	return (0);
}

static int
pkgxfer(char *srcinst, int options)
{
	int	r;
	struct pkginfo info;
	FILE	*fp, *pp;
	char	*pt, *src, *dst;
	char	dstdir[PATH_MAX],
		temp[PATH_MAX],
		srcdir[PATH_MAX],
		cmd[CMDSIZE],
		pkgname[NON_ABI_NAMELNGTH];
	int	i, n, part, nparts, maxpartsize, curpartcnt, iscomp;
	char	volnos[128], tmpvol[128];
	struct	statvfs64 svfsb;
	longlong_t free_blocks;
	struct	stat	srcstat;

	info.pkginst = NULL; /* required initialization */

	/*
	 * when this routine is entered, the first part of
	 * the package to transfer is already available in
	 * the directory indicated by 'src' --- unless the
	 * source device is a datstream, in which case only
	 * the pkginfo and pkgmap files are available in 'src'
	 */
	src = srcdev.dirname;
	dst = dstdev.dirname;

	if (!(options & PT_SILENT))
		(void) fprintf(stderr, pkg_gt(MSG_TRANSFER), srcinst);
	(void) strlcpy(dstinst, srcinst, sizeof (dstinst));

	if (!(options & PT_ODTSTREAM)) {
		/* destination is a (possibly mounted) directory */
		(void) snprintf(dstdir, sizeof (dstdir),
		    "%s/%s", dst, dstinst);

		/*
		 * need to check destination directory to assure
		 * that we will not be duplicating a package which
		 * already resides there (though we are allowed to
		 * overwrite the same version)
		 */
		pkgdir = src;
		if (fpkginfo(&info, srcinst)) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_NOEXISTS), srcinst);
			(void) fpkginfo(&info, NULL);
			return (1);
		}
		pkgdir = dst;

		(void) strlcpy(temp, srcinst, sizeof (temp));
		if (pt = strchr(temp, '.'))
			*pt = '\0';
		(void) strlcat(temp, ".*", sizeof (temp));

		if (pt = fpkginst(temp, info.arch, info.version)) {
			/*
			 * the same instance already exists, although
			 * its pkgid might be different
			 */
			if (options & PT_OVERWRITE) {
				(void) strlcpy(dstinst, pt, sizeof (dstinst));
				(void) snprintf(dstdir, sizeof (dstdir),
				    "%s/%s", dst, dstinst);
			} else {
				progerr(pkg_gt(ERR_TRANSFER));
				logerr(pkg_gt(MSG_DUPVERS), srcinst);
				(void) fpkginfo(&info, NULL);
				(void) fpkginst(NULL);
				return (2);
			}
		} else if (options & PT_RENAME) {
			/*
			 * find next available instance by appending numbers
			 * to the package abbreviation until the instance
			 * does not exist in the destination directory
			 */
			if (pt = strchr(temp, '.'))
				*pt = '\0';
			for (i = 2; (access(dstdir, 0) == 0); i++) {
				(void) snprintf(dstinst, sizeof (dstinst),
				    "%s.%d", temp, i);
				(void) snprintf(dstdir, sizeof (dstdir),
				    "%s/%s", dst, dstinst);
			}
		} else if (options & PT_OVERWRITE) {
			/*
			 * we're allowed to overwrite, but there seems
			 * to be no valid package to overwrite, and we are
			 * not allowed to rename the destination, so act
			 * as if we weren't given permission to overwrite
			 * --- this keeps us from removing a destination
			 * instance which is named the same as the source
			 * instance, but really reflects a different pkg!
			 */
			options &= (~PT_OVERWRITE);
		}
		(void) fpkginfo(&info, NULL);
		(void) fpkginst(NULL);

		if (ckoverwrite(dst, dstinst, options))
			return (2);

		if (isdir(dstdir) && mkdir(dstdir, 0755)) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_MKDIR), dstdir);
			return (1);
		}

		(void) snprintf(srcdir, sizeof (srcdir),
		    "%s/%s", src, srcinst);
		if (stat(srcdir, &srcstat) != -1) {
			if (chmod(dstdir, (srcstat.st_mode & S_IAMB)) == -1) {
				progerr(pkg_gt(ERR_TRANSFER));
				logerr(pkg_gt(MSG_CHMODDIR), dstdir);
				return (1);
			}
		} else {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_STATDIR), srcdir);
			return (1);
		}
	}

	if (!(options & PT_SILENT) && strcmp(dstinst, srcinst))
		(void) fprintf(stderr, pkg_gt(MSG_RENAME), dstinst);

	(void) snprintf(srcdir, sizeof (srcdir), "%s/%s", src, srcinst);
	if (chdir(srcdir)) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_CHDIR), srcdir);
		return (1);
	}

	if (ids_name) {	/* unpack the datatstream into a directory */
		/*
		 * transfer pkginfo & pkgmap first
		 */
		(void) snprintf(cmd, sizeof (cmd),
		    "%s -pudm %s", CPIOPROC, dstdir);
		if ((pp = epopen(cmd, "w")) == NULL) {
			rpterr();
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_POPEN), cmd, errno);
			return (1);
		}
		(void) fprintf(pp, "%s\n%s\n", PKGINFO, PKGMAP);

		(void) sighold(SIGINT);
		(void) sighold(SIGHUP);
		r = epclose(pp);
		(void) sigrelse(SIGINT);
		(void) sigrelse(SIGHUP);

		if (r != 0) {
			rpterr();
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_PCLOSE), cmd, errno);
			return (1);
		}

		if (options & PT_INFO_ONLY)
			return (0); /* don't transfer objects */

		if (chdir(dstdir)) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_CHDIR), dstdir);
			return (1);
		}

		/*
		 * for each part of the package, use cpio() to
		 * unpack the archive into the destination directory
		 */
		nparts = ds_findpkg(srcdev.cdevice, srcinst);
		if (nparts < 0) {
			progerr(pkg_gt(ERR_TRANSFER));
			return (1);
		}
		for (part = 1; part <= nparts; /* void */) {
			if (ds_getpkg(srcdev.cdevice, part, dstdir)) {
				progerr(pkg_gt(ERR_TRANSFER));
				return (1);
			}
			part++;
			if (dstdev.mount) {
				(void) chdir("/");
				if (pkgumount(&dstdev))
					return (1);
				if (part <= nparts) {
					if (n = pkgmount(&dstdev, NULL, part+1,
					    nparts, 1))
						return (n);
					if (ckoverwrite(dst, dstinst, options))
						return (1);
					if (isdir(dstdir) &&
					    mkdir(dstdir, 0755)) {
						progerr(
						    pkg_gt(ERR_TRANSFER));
						logerr(pkg_gt(MSG_MKDIR),
						    dstdir);
						return (1);
					}
					/*
					 * since volume is removable, each part
					 * must contain a duplicate of the
					 * pkginfo file to properly identify the
					 * volume
					 */
					if (chdir(srcdir)) {
						progerr(
						    pkg_gt(ERR_TRANSFER));
						logerr(pkg_gt(MSG_CHDIR),
						    srcdir);
						return (1);
					}
					if ((pp = epopen(cmd, "w")) == NULL) {
						rpterr();
						progerr(
						    pkg_gt(ERR_TRANSFER));
						logerr(pkg_gt(MSG_POPEN),
						    cmd, errno);
						return (1);
					}
					(void) fprintf(pp, "pkginfo");

					(void) sighold(SIGINT);
					(void) sighold(SIGHUP);
					r = epclose(pp);
					(void) sigrelse(SIGINT);
					(void) sigrelse(SIGHUP);

					if (r != 0) {
						rpterr();
						progerr(
						    pkg_gt(ERR_TRANSFER));
						logerr(pkg_gt(MSG_PCLOSE),
						    cmd, errno);
						return (1);
					}
					if (chdir(dstdir)) {
						progerr(
						    pkg_gt(ERR_TRANSFER));
						logerr(pkg_gt(MSG_CHDIR),
						    dstdir);
						return (1);
					}
				}
			}
		}
		return (0);
	}

	if ((fp = fopen(PKGMAP, "r")) == NULL) {
		progerr(pkg_gt(ERR_TRANSFER));
		logerr(pkg_gt(MSG_NOPKGMAP), srcinst);
		return (1);
	}

	nparts = 1;
	if (!rd_map_size(fp, &nparts, &maxpartsize, &compressedsize))
		return (1);
	else
		(void) fclose(fp);

	if (srcdev.mount) {
		if (ckvolseq(srcdir, 1, nparts)) {
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_SEQUENCE));
			return (1);
		}
	}

	/* write each part of this package */
	if (options & PT_ODTSTREAM) {
		char line[128];
		(void) mgets(line, 128);
		curpartcnt = -1;
		/* LINTED E_SEC_SCANF_UNBOUNDED_COPY */
		if (sscanf(line, "%s %d %d %[ 0-9]", pkgname, &nparts,
		    &maxpartsize, volnos) == 4) {
			(void) sscanf(volnos,
			    "%d %[ 0-9]", &curpartcnt, tmpvol);
			(void) strlcpy(volnos, tmpvol, sizeof (volnos));
		}
	}

	for (part = 1; part <= nparts; /* void */) {
		if (curpartcnt == 0 && (options & PT_ODTSTREAM)) {
			char prompt[128];
			int index;
			ds_volno++;
			(void) ds_close(0);
			(void) sprintf(prompt,
			    pkg_gt("Insert %%v %d of %d into %%p"),
			    ds_volno, ds_volcnt);
			if (n = getvol(ods_name, NULL, DM_FORMAT, prompt))
				return (n);
			if ((ds_fd = open(dstdev.cdevice, O_WRONLY)) < 0) {
				progerr(pkg_gt(ERR_TRANSFER));
				logerr(pkg_gt(MSG_OPEN), dstdev.cdevice,
				    errno);
				return (1);
			}
			if (ds_ginit(dstdev.cdevice) < 0) {
				progerr(pkg_gt(ERR_TRANSFER));
				logerr(pkg_gt(MSG_OPEN), dstdev.cdevice,
				    errno);
				(void) ds_close(0);
				return (1);
			}

			(void) sscanf(volnos, "%d %[ 0-9]", &index, tmpvol);
			(void) strlcpy(volnos, tmpvol, sizeof (volnos));
			curpartcnt += index;
		}

		if (options & PT_INFO_ONLY)
			nparts = 0;

		if (part == 1) {
			(void) snprintf(cmd, sizeof (cmd),
			    "find %s %s", PKGINFO, PKGMAP);
			if (nparts && (isdir(INSTALL) == 0)) {
				(void) strlcat(cmd, " ", sizeof (cmd));
				(void) strlcat(cmd, INSTALL, sizeof (cmd));
			}
		} else
			(void) snprintf(cmd, sizeof (cmd), "find %s", PKGINFO);

		if (nparts > 1) {
			(void) snprintf(temp, sizeof (temp),
			    "%s.%d", RELOC, part);
			if (iscpio(temp, &iscomp) || isdir(temp) == 0) {
				(void) strlcat(cmd, " ", sizeof (cmd));
				(void) strlcat(cmd, temp, sizeof (cmd));
			}
			(void) snprintf(temp, sizeof (temp),
			    "%s.%d", ROOT, part);
			if (iscpio(temp, &iscomp) || isdir(temp) == 0) {
				(void) strlcat(cmd, " ", sizeof (cmd));
				(void) strlcat(cmd, temp, sizeof (cmd));
			}
			(void) snprintf(temp, sizeof (temp),
			    "%s.%d", ARCHIVE, part);
			if (isdir(temp) == 0) {
				(void) strlcat(cmd, " ", sizeof (cmd));
				(void) strlcat(cmd, temp, sizeof (cmd));
			}
		} else if (nparts) {
			for (i = 0; reloc_names[i] != NULL; i++) {
				if (iscpio(reloc_names[i], &iscomp) ||
				    isdir(reloc_names[i]) == 0) {
					(void) strlcat(cmd, " ", sizeof (cmd));
					(void) strlcat(cmd, reloc_names[i],
					    sizeof (cmd));
				}
			}
			for (i = 0; root_names[i] != NULL; i++) {
				if (iscpio(root_names[i], &iscomp) ||
				    isdir(root_names[i]) == 0) {
					(void) strlcat(cmd, " ", sizeof (cmd));
					(void) strlcat(cmd, root_names[i],
					    sizeof (cmd));
				}
			}
			if (isdir(ARCHIVE) == 0) {
				(void) strlcat(cmd, " ", sizeof (cmd));
				(void) strlcat(cmd, ARCHIVE, sizeof (cmd));
			}
		}
		if (options & PT_ODTSTREAM) {
			(void) snprintf(cmd + strlen(cmd),
			    sizeof (cmd) - strlen(cmd),
			    " -print | %s -ocD -C %d",
			    CPIOPROC, (int)BLK_SIZE);
		} else {
			if (statvfs64(dstdir, &svfsb) == -1) {
				progerr(pkg_gt(ERR_TRANSFER));
				logerr(pkg_gt(MSG_STATVFS), dstdir, errno);
				return (1);
			}

			free_blocks = (((long)svfsb.f_frsize > 0) ?
			    howmany(svfsb.f_frsize, DEV_BSIZE) :
			    howmany(svfsb.f_bsize, DEV_BSIZE)) * svfsb.f_bavail;

			if ((has_comp_size ? compressedsize : maxpartsize) >
			    free_blocks) {
				progerr(pkg_gt(ERR_TRANSFER));
				logerr(pkg_gt(MSG_NOSPACE),
				    has_comp_size ?
				    (long)compressedsize : (long)maxpartsize,
				    free_blocks);
				return (1);
			}
			(void) snprintf(cmd + strlen(cmd),
			    sizeof (cmd) - strlen(cmd),
			    " -print | %s -pdum %s",
			    CPIOPROC, dstdir);
		}

		n = esystem(cmd, -1, (options & PT_ODTSTREAM) ? ds_fd : -1);
		if (n) {
			rpterr();
			progerr(pkg_gt(ERR_TRANSFER));
			logerr(pkg_gt(MSG_CMDFAIL), cmd, n);
			return (1);
		}

		part++;
		if (srcdev.mount && (nparts > 1)) {
			/* unmount current source volume */
			(void) chdir("/");
			if (pkgumount(&srcdev))
				return (1);
			/* loop until volume is mounted successfully */
			while (part <= nparts) {
				/* read only */
				n = pkgmount(&srcdev, NULL, part, nparts, 1);
				if (n)
					return (n);
				if (chdir(srcdir)) {
					progerr(pkg_gt(ERR_TRANSFER));
					logerr(pkg_gt(MSG_CORRUPT));
					(void) chdir("/");
					(void) pkgumount(&srcdev);
					continue;
				}
				if (ckvolseq(srcdir, part, nparts)) {
					(void) chdir("/");
					(void) pkgumount(&srcdev);
					continue;
				}
				break;
			}
		}
		if (!(options & PT_ODTSTREAM) && dstdev.mount) {
			/* unmount current volume */
			if (pkgumount(&dstdev))
				return (1);
			/* loop until next volume is mounted successfully */
			while (part <= nparts) {
				/* writable */
				n = pkgmount(&dstdev, NULL, part, nparts, 1);
				if (n)
					return (n);
				if (ckoverwrite(dst, dstinst, options))
					continue;
				if (isdir(dstdir) && mkdir(dstdir, 0755)) {
					progerr(pkg_gt(ERR_TRANSFER));
					logerr(pkg_gt(MSG_MKDIR), dstdir);
					continue;
				}
				break;
			}
		}

		if ((options & PT_ODTSTREAM) && part <= nparts) {
			if (curpartcnt >= 0 && part > curpartcnt) {
				char prompt[128];
				int index;
				ds_volno++;
				if (ds_close(0))
					return (1);
				(void) sprintf(prompt,
				    pkg_gt("Insert %%v %d of %d into %%p"),
				    ds_volno, ds_volcnt);
				if (n = getvol(ods_name, NULL, DM_FORMAT,
				    prompt))
					return (n);
				if ((ds_fd = open(dstdev.cdevice, 1)) < 0) {
					progerr(pkg_gt(ERR_TRANSFER));
					logerr(pkg_gt(MSG_OPEN),
					    dstdev.cdevice, errno);
					return (1);
				}
				if (ds_ginit(dstdev.cdevice) < 0) {
					progerr(pkg_gt(ERR_TRANSFER));
					logerr(pkg_gt(MSG_OPEN),
					    dstdev.cdevice, errno);
					(void) ds_close(0);
					return (1);
				}

				(void) sscanf(volnos, "%d %[ 0-9]", &index,
				    tmpvol);
				(void) strlcpy(volnos, tmpvol, sizeof (volnos));
				curpartcnt += index;
			}
		}

	}
	return (0);
}

static void
sigtrap(int signo)
{
	_NOTE(ARGUNUSED(signo));
	signal_received++;
}

static void
cleanup(void)
{
	(void) chdir("/");
	if (tmpdir) {
		(void) rrmdir(tmpdir);
		free(tmpdir);
		tmpdir = NULL;
	}

	if (tmppath) {
		/* remove any previous tmppath stuff */
		(void) rrmdir(tmppath);
		free(tmppath);
		tmppath = NULL;
	}

	if (tmpsymdir) {
		/* remove temp symbolic links made for signed pkg */
		(void) rrmdir(tmpsymdir);
		free(tmpsymdir);
		tmpsymdir = NULL;
	}

	if (srcdev.mount && !ids_name)
		(void) pkgumount(&srcdev);
	if (dstdev.mount && !ods_name)
		(void) pkgumount(&dstdev);
	(void) ds_close(1);
}
