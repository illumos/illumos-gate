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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lofiadm - administer lofi(7d). Very simple, add and remove file<->device
 * associations, and display status. All the ioctls are private between
 * lofi and lofiadm, and so are very simple - device information is
 * communicated via a minor number.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/lofi.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <stdio.h>
#include <fcntl.h>
#include <locale.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <libdevinfo.h>
#include <libgen.h>
#include <ctype.h>
#include <dlfcn.h>
#include "utils.h"

static const char USAGE[] =
	"Usage: %s -a file [ device ]\n"
	"       %s -d file | device \n"
	"       %s -C [algorithm] [-s segment_size] file \n"
	"       %s -U file \n"
	"       %s [ device | file ]\n";

static const char *pname;
static int	addflag = 0;
static int	deleteflag = 0;
static int	errflag = 0;
static int	compressflag = 0;
static int 	uncompressflag = 0;

static int gzip_compress(void *src, size_t srclen, void *dst,
	size_t *destlen, int level);

lofi_compress_info_t lofi_compress_table[LOFI_COMPRESS_FUNCTIONS] = {
	{NULL,  gzip_compress,  6,	"gzip"}, /* default */
	{NULL,	gzip_compress,	6,	"gzip-6"},
	{NULL,	gzip_compress,	9, 	"gzip-9"}
};

#define	FORMAT 			"%-20s     %-30s	%s\n"
#define	NONE			"-"
#define	COMPRESS		"Compressed"
#define	COMPRESS_ALGORITHM	"gzip"
#define	COMPRESS_THRESHOLD	2048
#define	SEGSIZE			131072
#define	BLOCK_SIZE		512
#define	KILOBYTE		1024
#define	MEGABYTE		(KILOBYTE * KILOBYTE)
#define	GIGABYTE		(KILOBYTE * MEGABYTE)
#define	LIBZ			"libz.so"

static int (*compress2p)(void *, ulong_t *, void *, size_t, int) = NULL;

static int gzip_compress(void *src, size_t srclen, void *dst,
	size_t *dstlen, int level)
{
	void *libz_hdl = NULL;

	/*
	 * The first time we are called, attempt to dlopen()
	 * libz.so and get a pointer to the compress2() function
	 */
	if (compress2p == NULL) {
		if ((libz_hdl = openlib(LIBZ)) == NULL)
			die(gettext("could not find %s. "
			    "gzip compression unavailable\n"), LIBZ);

		if ((compress2p =
		    (int (*)(void *, ulong_t *, void *, size_t, int))
		    dlsym(libz_hdl, "compress2")) == NULL) {
			closelib();
			die(gettext("could not find the correct %s. "
			    "gzip compression unavailable\n"), LIBZ);
		}
	}

	if ((*compress2p)(dst, (ulong_t *)dstlen, src, srclen, level) != 0)
		return (-1);
	return (0);
}

/*
 * Print the list of all the mappings. Including a header.
 */
static void
print_mappings(int fd)
{
	struct lofi_ioctl li;
	int	minor;
	int	maxminor;
	char	path[MAXPATHLEN];
	char	options[MAXPATHLEN];

	li.li_minor = 0;
	if (ioctl(fd, LOFI_GET_MAXMINOR, &li) == -1) {
		perror("ioctl");
		exit(E_ERROR);
	}

	maxminor = li.li_minor;

	(void) printf(FORMAT, "Block Device", "File", "Options");
	for (minor = 1; minor <= maxminor; minor++) {
		li.li_minor = minor;
		if (ioctl(fd, LOFI_GET_FILENAME, &li) == -1) {
			if (errno == ENXIO)
				continue;
			perror("ioctl");
			break;
		}
		(void) snprintf(path, sizeof (path), "/dev/%s/%d",
		    LOFI_BLOCK_NAME, minor);
		if (li.li_algorithm[0] == '\0')
			(void) snprintf(options, sizeof (options), "%s", NONE);
		else
			(void) snprintf(options, sizeof (options),
			    COMPRESS "(%s)", li.li_algorithm);

		(void) printf(FORMAT, path, li.li_filename, options);
	}
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(USAGE), pname, pname,
	    pname, pname, pname);
	exit(E_USAGE);
}

/*
 * Translate a lofi device name to a minor number. We might be asked
 * to do this when there is no association (such as when the user specifies
 * a particular device), so we can only look at the string.
 */
static int
name_to_minor(const char *devicename)
{
	int	minor;

	if (sscanf(devicename, "/dev/" LOFI_BLOCK_NAME "/%d", &minor) == 1) {
		return (minor);
	}
	if (sscanf(devicename, "/dev/" LOFI_CHAR_NAME "/%d", &minor) == 1) {
		return (minor);
	}
	return (0);
}

/*
 * This might be the first time we've used this minor number. If so,
 * it might also be that the /dev links are in the process of being created
 * by devfsadmd (or that they'll be created "soon"). We cannot return
 * until they're there or the invoker of lofiadm might try to use them
 * and not find them. This can happen if a shell script is running on
 * an MP.
 */
static int sleeptime = 2;	/* number of seconds to sleep between stat's */
static int maxsleep = 120;	/* maximum number of seconds to sleep */

static void
wait_until_dev_complete(int minor)
{
	struct stat64 buf;
	int	cursleep;
	char	blkpath[MAXPATHLEN];
	char	charpath[MAXPATHLEN];
	di_devlink_handle_t hdl;


	(void) snprintf(blkpath, sizeof (blkpath), "/dev/%s/%d",
	    LOFI_BLOCK_NAME, minor);
	(void) snprintf(charpath, sizeof (charpath), "/dev/%s/%d",
	    LOFI_CHAR_NAME, minor);

	/* Check if links already present */
	if (stat64(blkpath, &buf) == 0 && stat64(charpath, &buf) == 0)
		return;

	/* First use di_devlink_init() */
	if (hdl = di_devlink_init("lofi", DI_MAKE_LINK)) {
		(void) di_devlink_fini(&hdl);
		goto out;
	}

	/*
	 * Under normal conditions, di_devlink_init(DI_MAKE_LINK) above will
	 * only fail if the caller is non-root. In that case, wait for
	 * link creation via sysevents.
	 */
	cursleep = 0;
	while (cursleep < maxsleep) {
		if ((stat64(blkpath, &buf) == -1) ||
		    (stat64(charpath, &buf) == -1)) {
			(void) sleep(sleeptime);
			cursleep += sleeptime;
			continue;
		}
		return;
	}

	/* one last try */

out:
	if (stat64(blkpath, &buf) == -1) {
		die(gettext("%s was not created"), blkpath);
	}
	if (stat64(charpath, &buf) == -1) {
		die(gettext("%s was not created"), charpath);
	}
}

/*
 * Add a device association. If devicename is NULL, let the driver
 * pick a device.
 */
static void
add_mapping(int lfd, const char *devicename, const char *filename,
    int *minor_created, int suppress)
{
	struct lofi_ioctl li;
	int	minor;

	if (devicename == NULL) {
		/* pick one */
		li.li_minor = 0;
		(void) strlcpy(li.li_filename, filename,
		    sizeof (li.li_filename));
		minor = ioctl(lfd, LOFI_MAP_FILE, &li);
		if (minor == -1) {
			die(gettext("could not map file %s"), filename);
		}
		wait_until_dev_complete(minor);
		/* print one picked */
		if (!suppress)
			(void) printf("/dev/%s/%d\n", LOFI_BLOCK_NAME, minor);

		/* fill in the minor if needed */
		if (minor_created != NULL) {
			*minor_created = minor;
		}
		return;
	}
	/* use device we were given */
	minor = name_to_minor(devicename);
	if (minor == 0) {
		die(gettext("malformed device name %s\n"), devicename);
	}
	(void) strlcpy(li.li_filename, filename, sizeof (li.li_filename));
	li.li_minor = minor;
	if (ioctl(lfd, LOFI_MAP_FILE_MINOR, &li) == -1) {
		die(gettext("could not map file %s to %s"), filename,
		    devicename);
	}
	wait_until_dev_complete(minor);
}

/*
 * Remove an association. Delete by device name if non-NULL, or by
 * filename otherwise.
 */
static void
delete_mapping(int lfd, const char *devicename, const char *filename,
    boolean_t force)
{
	struct lofi_ioctl li;

	li.li_force = force;
	if (devicename == NULL) {
		/* delete by filename */
		(void) strlcpy(li.li_filename, filename,
		    sizeof (li.li_filename));
		li.li_minor = 0;
		if (ioctl(lfd, LOFI_UNMAP_FILE, &li) == -1) {
			die(gettext("could not unmap file %s"), filename);
		}
		return;
	}
	/* delete by device */

	li.li_minor = name_to_minor(devicename);
	if (li.li_minor == 0) {
		die(gettext("malformed device name %s\n"), devicename);
	}
	if (ioctl(lfd, LOFI_UNMAP_FILE_MINOR, &li) == -1) {
		die(gettext("could not unmap device %s"), devicename);
	}
}

static void
print_one_mapping(int lfd, const char *devicename, const char *filename)
{
	struct lofi_ioctl li;

	if (devicename == NULL) {
		/* given filename, print devicename */
		li.li_minor = 0;
		(void) strlcpy(li.li_filename, filename,
		    sizeof (li.li_filename));
		if (ioctl(lfd, LOFI_GET_MINOR, &li) == -1) {
			die(gettext("could not find device for %s"), filename);
		}
		(void) printf("/dev/%s/%d\n", LOFI_BLOCK_NAME, li.li_minor);
		return;
	}

	/* given devicename, print filename */
	li.li_minor = name_to_minor(devicename);
	if (li.li_minor == 0) {
		die(gettext("malformed device name %s\n"), devicename);
	}
	if (ioctl(lfd, LOFI_GET_FILENAME, &li) == -1) {
		die(gettext("could not find filename for %s"), devicename);
	}
	(void) printf("%s\n", li.li_filename);
}

/*
 * Uncompress a file.
 *
 * First map the file in to establish a device
 * association, then read from it. On-the-fly
 * decompression will automatically uncompress
 * the file if it's compressed
 *
 * If the file is mapped and a device association
 * has been established, disallow uncompressing
 * the file until it is unmapped.
 */
static void
lofi_uncompress(int lfd, const char *filename)
{
	struct lofi_ioctl li;
	char buf[MAXBSIZE];
	char devicename[32];
	char tmpfilename[MAXPATHLEN];
	char *dir = NULL;
	char *file = NULL;
	int minor = 0;
	struct stat64 statbuf;
	int compfd = -1;
	int uncompfd = -1;
	ssize_t rbytes;

	/*
	 * Disallow uncompressing the file if it is
	 * already mapped.
	 */
	li.li_minor = 0;
	(void) strlcpy(li.li_filename, filename, sizeof (li.li_filename));
	if (ioctl(lfd, LOFI_GET_MINOR, &li) != -1)
		die(gettext("%s must be unmapped before uncompressing"),
		    filename);

	/* Zero length files don't need to be uncompressed */
	if (stat64(filename, &statbuf) == -1)
		die(gettext("stat: %s"), filename);
	if (statbuf.st_size == 0)
		return;

	add_mapping(lfd, NULL, filename, &minor, 1);
	(void) snprintf(devicename, sizeof (devicename), "/dev/%s/%d",
	    LOFI_BLOCK_NAME, minor);

	/* If the file isn't compressed, we just return */
	if ((ioctl(lfd, LOFI_CHECK_COMPRESSED, &li) == -1) ||
	    (li.li_algorithm == '\0')) {
		delete_mapping(lfd, devicename, filename, B_TRUE);
		return;
	}

	if ((compfd = open64(devicename, O_RDONLY | O_NONBLOCK)) == -1) {
		delete_mapping(lfd, devicename, filename, B_TRUE);
		die(gettext("open: %s"), filename);
	}
	/* Create a temp file in the same directory */
	dir = strdup(filename);
	dir = dirname(dir);
	file = strdup(filename);
	file = basename(file);
	(void) snprintf(tmpfilename, sizeof (tmpfilename),
	    "%s/.%sXXXXXX", dir, file);

	if ((uncompfd = mkstemp64(tmpfilename)) == -1) {
		(void) close(compfd);
		delete_mapping(lfd, devicename, filename, B_TRUE);
		free(dir);
		free(file);
		return;
	}

	/*
	 * Set the mode bits and the owner of this temporary
	 * file to be that of the original uncompressed file
	 */
	(void) fchmod(uncompfd, statbuf.st_mode);

	if (fchown(uncompfd, statbuf.st_uid, statbuf.st_gid) == -1) {
		(void) close(compfd);
		(void) close(uncompfd);
		delete_mapping(lfd, devicename, filename, B_TRUE);
		free(dir);
		free(file);
		return;
	}

	/* Now read from the device in MAXBSIZE-sized chunks */
	for (;;) {
		rbytes = read(compfd, buf, sizeof (buf));

		if (rbytes <= 0)
			break;

		if (write(uncompfd, buf, rbytes) != rbytes) {
			rbytes = -1;
			break;
		}
	}

	(void) close(compfd);
	(void) close(uncompfd);
	free(dir);
	free(file);

	/* Delete the mapping */
	delete_mapping(lfd, devicename, filename, B_TRUE);

	/*
	 * If an error occured while reading or writing, rbytes will
	 * be negative
	 */
	if (rbytes < 0) {
		(void) unlink(tmpfilename);
		die(gettext("could not read from %s"), filename);
	}

	/* Rename the temp file to the actual file */
	if (rename(tmpfilename, filename) == -1)
		(void) unlink(tmpfilename);
}

/*
 * Compress a file
 */
static void
lofi_compress(int lfd, const char *filename, int compress_index,
    uint32_t segsize)
{
	struct lofi_ioctl lic;
	lofi_compress_info_t *li;
	char tmpfilename[MAXPATHLEN];
	char comp_filename[MAXPATHLEN];
	char algorithm[MAXALGLEN];
	char *dir = NULL, *file = NULL;
	uchar_t *uncompressed_seg = NULL;
	uchar_t *compressed_seg = NULL;
	uint32_t compressed_segsize;
	uint32_t len_compressed, count;
	uint32_t index_entries, index_sz;
	uint64_t *index = NULL;
	uint64_t offset;
	size_t real_segsize;
	struct stat64 statbuf;
	int compfd = -1, uncompfd = -1;
	int tfd = -1;
	ssize_t rbytes, wbytes, lastread;
	int i, type;

	/*
	 * Disallow compressing the file if it is
	 * already mapped
	 */
	lic.li_minor = 0;
	(void) strlcpy(lic.li_filename, filename, sizeof (lic.li_filename));
	if (ioctl(lfd, LOFI_GET_MINOR, &lic) != -1)
		die(gettext("%s must be unmapped before compressing"),
		    filename);

	li = &lofi_compress_table[compress_index];

	/*
	 * The size of the buffer to hold compressed data must
	 * be slightly larger than the compressed segment size.
	 *
	 * The compress functions use part of the buffer as
	 * scratch space to do calculations.
	 * Ref: http://www.zlib.net/manual.html#compress2
	 */
	compressed_segsize = segsize + (segsize >> 6);
	compressed_seg = (uchar_t *)malloc(compressed_segsize + SEGHDR);
	uncompressed_seg = (uchar_t *)malloc(segsize);

	if (compressed_seg == NULL || uncompressed_seg == NULL)
		die(gettext("No memory"));

	if ((uncompfd = open64(filename, O_RDONLY|O_LARGEFILE, 0)) == -1)
		die(gettext("open: %s"), filename);

	if (fstat64(uncompfd, &statbuf) == -1) {
		(void) close(uncompfd);
		die(gettext("fstat: %s"), filename);
	}

	/* Zero length files don't need to be compressed */
	if (statbuf.st_size == 0) {
		(void) close(uncompfd);
		return;
	}

	/*
	 * Create temporary files in the same directory that
	 * will hold the intermediate data
	 */
	dir = strdup(filename);
	dir = dirname(dir);
	file = strdup(filename);
	file = basename(file);
	(void) snprintf(tmpfilename, sizeof (tmpfilename),
	    "%s/.%sXXXXXX", dir, file);
	(void) snprintf(comp_filename, sizeof (comp_filename),
	    "%s/.%sXXXXXX", dir, file);

	if ((tfd = mkstemp64(tmpfilename)) == -1)
		goto cleanup;

	if ((compfd = mkstemp64(comp_filename)) == -1)
		goto cleanup;

	/*
	 * Set the mode bits and owner of the compressed
	 * file to be that of the original uncompressed file
	 */
	(void) fchmod(compfd, statbuf.st_mode);

	if (fchown(compfd, statbuf.st_uid, statbuf.st_gid) == -1)
		goto cleanup;

	/*
	 * Calculate the number of index entries required.
	 * index entries are stored as an array. adding
	 * a '2' here accounts for the fact that the last
	 * segment may not be a multiple of the segment size
	 */
	index_sz = (statbuf.st_size / segsize) + 2;
	index = malloc(sizeof (*index) * index_sz);

	if (index == NULL)
		goto cleanup;

	offset = 0;
	lastread = segsize;
	count = 0;

	/*
	 * Now read from the uncompressed file in 'segsize'
	 * sized chunks, compress what was read in and
	 * write it out to a temporary file
	 */
	for (;;) {
		rbytes = read(uncompfd, uncompressed_seg, segsize);

		if (rbytes <= 0)
			break;

		if (lastread < segsize)
			goto cleanup;

		/*
		 * Account for the first byte that
		 * indicates whether a segment is
		 * compressed or not
		 */
		real_segsize = segsize - 1;
		(void) li->l_compress(uncompressed_seg, rbytes,
		    compressed_seg + SEGHDR, &real_segsize, li->l_level);

		/*
		 * If the length of the compressed data is more
		 * than a threshold then there isn't any benefit
		 * to be had from compressing this segment - leave
		 * it uncompressed.
		 *
		 * NB. In case an error occurs during compression (above)
		 * the 'real_segsize' isn't changed. The logic below
		 * ensures that that segment is left uncompressed.
		 */
		len_compressed = real_segsize;
		if (real_segsize > segsize - COMPRESS_THRESHOLD) {
			(void) memcpy(compressed_seg + SEGHDR, uncompressed_seg,
			    rbytes);
			type = UNCOMPRESSED;
			len_compressed = rbytes;
		} else {
			type = COMPRESSED;
		}

		/*
		 * Set the first byte or the SEGHDR to
		 * indicate if it's compressed or not
		 */
		*compressed_seg = type;
		wbytes = write(tfd, compressed_seg, len_compressed + SEGHDR);
		if (wbytes != (len_compressed + SEGHDR)) {
			rbytes = -1;
			break;
		}

		index[count] = BE_64(offset);
		offset += wbytes;
		lastread = rbytes;
		count++;
	}

	(void) close(uncompfd);

	if (rbytes < 0)
		goto cleanup;
	/*
	 * The last index entry is a sentinel entry. It does not point to
	 * an actual compressed segment but helps in computing the size of
	 * the compressed segment. The size of each compressed segment is
	 * computed by subtracting the current index value from the next
	 * one (the compressed blocks are stored sequentially)
	 */
	index[count++] = BE_64(offset);

	/*
	 * Now write the compressed data along with the
	 * header information to this file which will
	 * later be renamed to the original uncompressed
	 * file name
	 *
	 * The header is as follows -
	 *
	 * Signature (name of the compression algorithm)
	 * Compression segment size (a multiple of 512)
	 * Number of index entries
	 * Size of the last block
	 * The array containing the index entries
	 *
	 * the header is always stored in network byte
	 * order
	 */
	(void) bzero(algorithm, sizeof (algorithm));
	(void) strlcpy(algorithm, li->l_name, sizeof (algorithm));
	if (write(compfd, algorithm, sizeof (algorithm))
	    != sizeof (algorithm))
		goto cleanup;

	segsize = htonl(segsize);
	if (write(compfd, &segsize, sizeof (segsize)) != sizeof (segsize))
		goto cleanup;

	index_entries = htonl(count);
	if (write(compfd, &index_entries, sizeof (index_entries)) !=
	    sizeof (index_entries))
		goto cleanup;

	lastread = htonl(lastread);
	if (write(compfd, &lastread, sizeof (lastread)) != sizeof (lastread))
		goto cleanup;

	for (i = 0; i < count; i++) {
		if (write(compfd, index + i, sizeof (*index)) !=
		    sizeof (*index))
			goto cleanup;
	}

	/* Header is written, now write the compressed data */
	if (lseek(tfd, 0, SEEK_SET) != 0)
		goto cleanup;

	rbytes = wbytes = 0;

	for (;;) {
		rbytes = read(tfd, compressed_seg, compressed_segsize + SEGHDR);

		if (rbytes <= 0)
			break;

		if (write(compfd, compressed_seg, rbytes) != rbytes)
			goto cleanup;
	}

	if (fstat64(compfd, &statbuf) == -1)
		goto cleanup;

	/*
	 * Round up the compressed file size to be a multiple of
	 * DEV_BSIZE. lofi(7D) likes it that way.
	 */
	if ((offset = statbuf.st_size % DEV_BSIZE) > 0) {

		offset = DEV_BSIZE - offset;

		for (i = 0; i < offset; i++)
			uncompressed_seg[i] = '\0';
		if (write(compfd, uncompressed_seg, offset) != offset)
			goto cleanup;
	}
	(void) close(compfd);
	(void) close(tfd);
	(void) unlink(tmpfilename);
cleanup:
	if (rbytes < 0) {
		if (tfd != -1)
			(void) unlink(tmpfilename);
		if (compfd != -1)
			(void) unlink(comp_filename);
		die(gettext("error compressing file %s"), filename);
	} else {
		/* Rename the compressed file to the actual file */
		if (rename(comp_filename, filename) == -1) {
			(void) unlink(comp_filename);
			die(gettext("error compressing file %s"), filename);
		}
	}
	if (compressed_seg != NULL)
		free(compressed_seg);
	if (uncompressed_seg != NULL)
		free(uncompressed_seg);
	if (dir != NULL)
		free(dir);
	if (file != NULL)
		free(file);
	if (index != NULL)
		free(index);
	if (compfd != -1)
		(void) close(compfd);
	if (uncompfd != -1)
		(void) close(uncompfd);
	if (tfd != -1)
		(void) close(tfd);
}

static int
lofi_compress_select(const char *algname)
{
	int i;

	for (i = 0; i < LOFI_COMPRESS_FUNCTIONS; i++) {
		if (strcmp(lofi_compress_table[i].l_name, algname) == 0)
			return (i);
	}
	return (-1);
}

static void
check_algorithm_validity(const char *algname, int *compress_index)
{
	*compress_index = lofi_compress_select(algname);
	if (*compress_index < 0)
		die(gettext("invalid algorithm name: %s\n"), algname);
}

static void
check_file_validity(const char *filename)
{
	struct stat64 buf;
	int 	error;
	int	fd = -1;

	fd = open64(filename, O_RDONLY);
	if (fd == -1) {
		die(gettext("open: %s"), filename);
	}
	error = fstat64(fd, &buf);
	if (error == -1) {
		die(gettext("fstat: %s"), filename);
	} else if (!S_ISLOFIABLE(buf.st_mode)) {
		die(gettext("%s is not a regular file, "
		    "block, or character device\n"),
		    filename);
	} else if ((buf.st_size % DEV_BSIZE) != 0) {
		die(gettext("size of %s is not a multiple "
		    "of %d\n"),
		    filename, DEV_BSIZE);
	}
	(void) close(fd);

	if (name_to_minor(filename) != 0) {
		die(gettext("cannot use " LOFI_DRIVER_NAME
		    " on itself\n"), NULL);
	}
}

static uint32_t
convert_to_num(const char *str)
{
	int len;
	uint32_t segsize, mult = 1;

	len = strlen(str);
	if (len && isalpha(str[len - 1])) {
		switch (str[len - 1]) {
		case 'k':
		case 'K':
			mult = KILOBYTE;
			break;
		case 'b':
		case 'B':
			mult = BLOCK_SIZE;
			break;
		case 'm':
		case 'M':
			mult = MEGABYTE;
			break;
		case 'g':
		case 'G':
			mult = GIGABYTE;
			break;
		default:
			die(gettext("invalid segment size %s\n"), str);
		}
	}

	segsize = atol(str);
	segsize *= mult;

	return (segsize);
}

int
main(int argc, char *argv[])
{
	int	lfd;
	int	c;
	const char *devicename = NULL;
	const char *filename = NULL;
	const char *algname = COMPRESS_ALGORITHM;
	int	openflag;
	int	minor;
	int 	compress_index;
	uint32_t segsize = SEGSIZE;
	static char *lofictl = "/dev/" LOFI_CTL_NAME;
	boolean_t force = B_FALSE;

	pname = getpname(argv[0]);

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "a:C:d:s:U:f")) != EOF) {
		switch (c) {
		case 'a':
			addflag = 1;
			filename = optarg;
			check_file_validity(filename);

			if (((argc - optind) > 0) && (*argv[optind] != '-')) {
				/* optional device */
				devicename = argv[optind];
				optind++;
			}
			break;
		case 'C':
			compressflag = 1;

			if (((argc - optind) > 0) &&
			    (*optarg == '-')) {
				check_algorithm_validity(algname,
				    &compress_index);
				optind--;
				break;
			} else if (((argc - optind) == 1) &&
			    (*argv[optind] != '-')) {
				algname = optarg;
				filename = argv[optind];
				optind++;
			} else if (((argc - optind) > 1) &&
			    (*argv[optind] == '-')) {
				algname = optarg;
				check_algorithm_validity(algname,
				    &compress_index);
				break;
			} else {
				filename = optarg;
			}

			check_file_validity(filename);
			check_algorithm_validity(algname, &compress_index);
			break;
		case 'd':
			deleteflag = 1;

			minor = name_to_minor(optarg);
			if (minor != 0)
				devicename = optarg;
			else
				filename = optarg;
			break;
		case 'f':
			force = B_TRUE;
			break;
		case 's':
			segsize = convert_to_num(optarg);

			if (segsize == 0 || segsize % DEV_BSIZE)
				die(gettext("segment size %s is invalid "
				    "or not a multiple of minimum block "
				    "size %ld\n"), optarg, DEV_BSIZE);

			filename = argv[optind];
			check_file_validity(filename);
			optind++;
			break;
		case 'U':
			uncompressflag = 1;
			filename = optarg;
			check_file_validity(filename);
			break;
		case '?':
		default:
			errflag = 1;
			break;
		}
	}
	if (errflag ||
	    (addflag && deleteflag) ||
	    ((compressflag || uncompressflag) && (addflag || deleteflag)))
		usage();

	switch (argc - optind) {
	case 0: /* no more args */
		break;
	case 1: /* one arg without options means print the association */
		if (addflag || deleteflag)
			usage();
		if (compressflag || uncompressflag)
			usage();
		minor = name_to_minor(argv[optind]);
		if (minor != 0)
			devicename = argv[optind];
		else
			filename = argv[optind];
		break;
	default:
		usage();
		break;
	}

	if (filename && !valid_abspath(filename))
		exit(E_ERROR);

	/*
	 * Here, we know the arguments are correct, the filename is an
	 * absolute path, it exists and is a regular file. We don't yet
	 * know that the device name is ok or not.
	 */
	/*
	 * Now to the real work.
	 */
	openflag = O_EXCL;
	if (addflag || deleteflag || compressflag || uncompressflag)
		openflag |= O_RDWR;
	else
		openflag |= O_RDONLY;
	lfd = open(lofictl, openflag);
	if (lfd == -1) {
		if ((errno == EPERM) || (errno == EACCES)) {
			die("you do not have permission to perform "
			    "that operation.\n");
		} else {
			die("%s", lofictl);
		}
		/*NOTREACHED*/
	}
	if (addflag)
		add_mapping(lfd, devicename, filename, NULL, 0);
	else if (compressflag)
		lofi_compress(lfd, filename, compress_index, segsize);
	else if (uncompressflag)
		lofi_uncompress(lfd, filename);
	else if (deleteflag)
		delete_mapping(lfd, devicename, filename, force);
	else if (filename || devicename)
		print_one_mapping(lfd, devicename, filename);
	else
		print_mappings(lfd);

	(void) close(lfd);
	closelib();
	return (E_SUCCESS);
}
