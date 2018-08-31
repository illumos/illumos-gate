/*
 * Copyright 2011-2017 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/stdbool.h>
#include <sys/sysmacros.h>
#include <sys/bootvfs.h>
#include <sys/filep.h>
#include <sys/sunddi.h>
#include <sys/ccompile.h>
#include <sys/queue.h>

/*
 * A cpio archive is just a sequence of files, each consisting of a header
 * (struct cpio_hdr) and the file contents.
 */

struct cpio_hdr {
	uint8_t		magic[6];
	uint8_t		dev[6];
	uint8_t		ino[6];
	uint8_t		mode[6];
	uint8_t		uid[6];
	uint8_t		gid[6];
	uint8_t		nlink[6];
	uint8_t		rdev[6];
	uint8_t		mtime[11];
	uint8_t		namesize[6];
	uint8_t		filesize[11];
	char		data[];
};

/*
 * This structure represents an open file.  The list of all open files is
 * rooted in the open_files global.
 */
struct cpio_file {
	/* pointers into the archive */
	const struct cpio_hdr *hdr;
	const char *path;		/* pointer into the archive */
	const void *data;		/* pointer into the archive */

	int fd;
	off_t off;
	struct bootstat stat;

	SLIST_ENTRY(cpio_file) next;
};

extern void *bkmem_alloc(size_t);
extern void bkmem_free(void *, size_t);

static void cpio_closeall(int flag);

static bool mounted;
static SLIST_HEAD(cpio_file_list, cpio_file)
    open_files = SLIST_HEAD_INITIALIZER(open_files);

static int
cpio_strcmp(const char *a, const char *b)
{
	while ((*a != '\0') && (*b != '\0') && (*a == *b)) {
		a++;
		b++;
	}

	if (*a == *b)
		return (0);
	if (*a < *b)
		return (-1);
	return (1);
}

/*
 * Returns the parsed number on success, or UINT64_MAX on error.  This is
 * ok because we will never deal with numbers that large in a cpio archive.
 */
static uint64_t
__get_uint64(const uint8_t *str, size_t len, const size_t output_size)
{
	uint64_t v;

	/* check that we can represent every number */
	if (len * 3 > output_size)
		return (UINT64_MAX);

	for (v = 0; len > 0; len--, str++) {
		const uint8_t c = *str;

		if ((c < '0') || (c > '7'))
			return (UINT64_MAX);

		v = (v * 8) + (c - '0');
	}

	return (v);
}

static bool
get_uint64(const uint8_t *str, size_t len, uint64_t *out)
{
	*out = __get_uint64(str, len, NBBY * sizeof (*out));
	return (*out != UINT64_MAX);
}

static bool
get_int64(const uint8_t *str, size_t len, int64_t *out)
{
	uint64_t tmp;

	tmp = __get_uint64(str, len, NBBY * sizeof (*out) - 1);

	*out = tmp;

	return (tmp != UINT64_MAX);
}

static bool
get_uint32(const uint8_t *str, size_t len, uint32_t *out)
{
	uint64_t tmp;

	tmp = __get_uint64(str, len, NBBY * sizeof (*out));

	*out = tmp;

	return (tmp != UINT64_MAX);
}

static bool
get_int32(const uint8_t *str, size_t len, int32_t *out)
{
	uint64_t tmp;

	tmp = __get_uint64(str, len, NBBY * sizeof (*out) - 1);

	*out = tmp;

	return (tmp != UINT64_MAX);
}

static void
add_open_file(struct cpio_file *file)
{
	SLIST_INSERT_HEAD(&open_files, file, next);
}

static void
remove_open_file(struct cpio_file *file)
{
	SLIST_REMOVE(&open_files, file, cpio_file, next);
}

static struct cpio_file *
find_open_file(int fd)
{
	struct cpio_file *file;

	if (fd < 0)
		return (NULL);

	SLIST_FOREACH(file, &open_files, next)
		if (file->fd == fd)
			return (file);

	return (NULL);
}

static const void *
read_ramdisk(size_t off, size_t len)
{
	const size_t first_block_offset = off % DEV_BSIZE;
	fileid_t tmpfile;

	/* return a dummy non-NULL pointer */
	if (len == 0)
		return ("");

	/* we have to read the stuff before the desired location as well */
	len += first_block_offset;

	tmpfile.fi_blocknum = off / DEV_BSIZE;
	tmpfile.fi_count = P2ROUNDUP_TYPED(len, DEV_BSIZE, size_t);
	tmpfile.fi_memp = NULL;

	if (diskread(&tmpfile) != 0)
		return (NULL);

	return (tmpfile.fi_memp + first_block_offset);
}

static bool
parse_stat(const struct cpio_hdr *hdr, struct bootstat *stat)
{
	if (!get_uint64(hdr->dev, sizeof (hdr->dev), &stat->st_dev))
		return (false);
	if (!get_uint64(hdr->ino, sizeof (hdr->ino), &stat->st_ino))
		return (false);
	if (!get_uint32(hdr->mode, sizeof (hdr->mode), &stat->st_mode))
		return (false);
	if (!get_int32(hdr->uid, sizeof (hdr->uid), &stat->st_uid))
		return (false);
	if (!get_int32(hdr->gid, sizeof (hdr->gid), &stat->st_gid))
		return (false);
	if (!get_uint32(hdr->nlink, sizeof (hdr->nlink), &stat->st_nlink))
		return (false);
	if (!get_uint64(hdr->rdev, sizeof (hdr->rdev), &stat->st_rdev))
		return (false);

	stat->st_mtim.tv_nsec = 0;
	if (!get_int64(hdr->mtime, sizeof (hdr->mtime), &stat->st_mtim.tv_sec))
		return (false);

	stat->st_atim = stat->st_mtim;
	stat->st_ctim = stat->st_mtim;

	if (!get_uint64(hdr->filesize, sizeof (hdr->filesize), &stat->st_size))
		return (false);

	stat->st_blksize = DEV_BSIZE;
	stat->st_blocks = P2ROUNDUP(stat->st_size, DEV_BSIZE);

	return (true);
}

/*
 * Check if specified header is for a file with a specific path.  If so,
 * fill in the file struct and return 0.  If not, return number of bytes to
 * skip over to get to the next header.  If an error occurs, -1 is returned.
 * If end of archive is reached, return -2 instead.
 */
static ssize_t
scan_archive_hdr(const struct cpio_hdr *hdr, size_t off,
    struct cpio_file *file, const char *wanted_path)
{
	struct bootstat stat;
	uint32_t namesize;
	uint64_t filesize;
	const char *path;
	const void *data;

	if ((hdr->magic[0] != '0') || (hdr->magic[1] != '7') ||
	    (hdr->magic[2] != '0') || (hdr->magic[3] != '7') ||
	    (hdr->magic[4] != '0') || (hdr->magic[5] != '7'))
		return (-1);

	if (!get_uint32(hdr->namesize, sizeof (hdr->namesize), &namesize))
		return (-1);
	if (!get_uint64(hdr->filesize, sizeof (hdr->filesize), &filesize))
		return (-1);

	/*
	 * We have the two sizes, let's try to read the name and file
	 * contents to make sure they are part of the ramdisk.
	 */

	off += offsetof(struct cpio_hdr, data[0]);
	path = read_ramdisk(off, namesize);
	data = read_ramdisk(off + namesize, filesize);

	/* either read failing is fatal */
	if (path == NULL || data == NULL)
		return (-1);

	if (cpio_strcmp(path, "TRAILER!!!") == 0)
		return (-2);

	if (cpio_strcmp(path, wanted_path) != 0)
		return (offsetof(struct cpio_hdr, data[namesize + filesize]));

	/*
	 * This is the file we want!
	 */

	if (!parse_stat(hdr, &stat))
		return (-1);

	file->hdr = hdr;
	file->path = path;
	file->data = data;
	file->stat = stat;

	return (0);
}

static int
find_filename(char *path, struct cpio_file *file)
{
	size_t off;

	/*
	 * The paths in the cpio boot archive omit the leading '/'.  So,
	 * skip checking for it.  If the searched for path does not include
	 * the leading path (it's a relative path), fail the lookup.
	 */
	if (path[0] != '/')
		return (-1);

	path++;

	/* now scan the archive for the relevant file */

	off = 0;

	for (;;) {
		const struct cpio_hdr *hdr;
		ssize_t size;

		hdr = read_ramdisk(off, sizeof (struct cpio_hdr));
		if (hdr == NULL)
			return (-1);

		size = scan_archive_hdr(hdr, off, file, path);
		if (size <= 0)
			return (size);

		off += size;
	}
}

/* ARGSUSED */
static int
bcpio_mountroot(char *str __unused)
{
	if (mounted)
		return (-1);

	mounted = true;

	return (0);
}

static int
bcpio_unmountroot(void)
{
	if (!mounted)
		return (-1);

	mounted = false;

	return (0);
}

/* ARGSUSED */
static int
bcpio_open(char *path, int flags __unused)
{
	static int filedes = 1;
	struct cpio_file temp_file;
	struct cpio_file *file;

	if (find_filename(path, &temp_file) != 0)
		return (-1);

	file = bkmem_alloc(sizeof (struct cpio_file));
	file->hdr = temp_file.hdr;
	file->path = temp_file.path;
	file->data = temp_file.data;
	file->stat = temp_file.stat;
	file->fd = filedes++;
	file->off = 0;

	add_open_file(file);

	return (file->fd);
}

static int
bcpio_close(int fd)
{
	struct cpio_file *file;

	file = find_open_file(fd);
	if (file == NULL)
		return (-1);

	remove_open_file(file);

	bkmem_free(file, sizeof (struct cpio_file));

	return (0);
}

/* ARGSUSED */
static void
bcpio_closeall(int flag __unused)
{
	struct cpio_file *file;

	while (!SLIST_EMPTY(&open_files)) {
		file = SLIST_FIRST(&open_files);

		if (bcpio_close(file->fd) != 0)
			printf("closeall invoked close(%d) failed\n", file->fd);
	}
}

static ssize_t
bcpio_read(int fd, caddr_t buf, size_t size)
{
	struct cpio_file *file;

	file = find_open_file(fd);
	if (file == NULL)
		return (-1);

	if (size == 0)
		return (0);

	if (file->off + size > file->stat.st_size)
		size = file->stat.st_size - file->off;

	bcopy((void *)((uintptr_t)file->data + file->off), buf, size);

	file->off += size;

	return (size);
}

static off_t
bcpio_lseek(int fd, off_t addr, int whence)
{
	struct cpio_file *file;

	file = find_open_file(fd);
	if (file == NULL)
		return (-1);

	switch (whence) {
		case SEEK_CUR:
			file->off += addr;
			break;
		case SEEK_SET:
			file->off = addr;
			break;
		case SEEK_END:
			file->off = file->stat.st_size;
			break;
		default:
			printf("lseek(): invalid whence value %d\n", whence);
			return (-1);
	}

	return (0);
}

static int
bcpio_fstat(int fd, struct bootstat *buf)
{
	const struct cpio_file *file;

	file = find_open_file(fd);
	if (file == NULL)
		return (-1);

	*buf = file->stat;

	return (0);
}

struct boot_fs_ops bcpio_ops = {
	.fsw_name		= "boot_cpio",
	.fsw_mountroot		= bcpio_mountroot,
	.fsw_unmountroot	= bcpio_unmountroot,
	.fsw_open		= bcpio_open,
	.fsw_close		= bcpio_close,
	.fsw_closeall		= bcpio_closeall,
	.fsw_read		= bcpio_read,
	.fsw_lseek		= bcpio_lseek,
	.fsw_fstat		= bcpio_fstat,
};
