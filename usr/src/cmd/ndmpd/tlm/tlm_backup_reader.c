/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <limits.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <pthread.h>
#include <archives.h>
#include <tlm.h>
#include <sys/fs/zfs.h>
#include <sys/mkdev.h>
#include <libzfs.h>
#include <libcmdutils.h>
#include <pwd.h>
#include <grp.h>
#include "tlm_proto.h"


static char *get_write_buffer(long size,
    long *actual_size,
    boolean_t zero,
    tlm_cmd_t *);
static int output_acl_header(sec_attr_t *,
    tlm_cmd_t *);
static int output_file_header(char *name,
    char *link,
    tlm_acls_t *,
    int section,
    tlm_cmd_t *);
static int output_xattr_header(char *fname,
    char *aname,
    int fd,
    tlm_acls_t *,
    int section,
    tlm_cmd_t *);

extern  libzfs_handle_t *zlibh;
extern	mutex_t zlib_mtx;

#define	S_ISPECIAL(a)	(S_ISLNK(a) || S_ISFIFO(a) || S_ISBLK(a) || \
	S_ISCHR(a))

/*
 * output_mem
 *
 * Gets a IO write buffer and copies memory to the that.
 */
static void
output_mem(tlm_cmd_t *local_commands, char *mem,
    int len)
{
	long actual_size, rec_size;
	char *rec;

	while (len > 0) {
		rec = get_write_buffer(len, &actual_size,
		    FALSE, local_commands);
		rec_size = min(actual_size, len);
		(void) memcpy(rec, mem, rec_size);
		mem += rec_size;
		len -= rec_size;
	}
}

/*
 * tlm_output_dir
 *
 * Put the directory information into the output buffers.
 */
int
tlm_output_dir(char *name, tlm_acls_t *tlm_acls,
    tlm_cmd_t *local_commands, tlm_job_stats_t *job_stats)
{
	u_longlong_t pos;

	/*
	 * Send the node or path history of the directory itself.
	 */
	pos = tlm_get_data_offset(local_commands);
	NDMP_LOG(LOG_DEBUG, "pos: %10lld  [%s]", pos, name);
	(void) tlm_log_fhnode(job_stats, name, "", &tlm_acls->acl_attr, pos);
	(void) tlm_log_fhpath_name(job_stats, name, &tlm_acls->acl_attr, pos);
	/* fhdir_cb is handled in ndmpd_tar3.c */

	(void) output_acl_header(&tlm_acls->acl_info,
	    local_commands);
	(void) output_file_header(name, "", tlm_acls, 0,
	    local_commands);

	return (0);
}

/*
 * tar_putdir
 *
 * Main dir backup function for tar
 */
int
tar_putdir(char *name, tlm_acls_t *tlm_acls,
    tlm_cmd_t *local_commands, tlm_job_stats_t *job_stats)
{
	int rv;

	rv = tlm_output_dir(name, tlm_acls, local_commands, job_stats);
	return (rv < 0 ? rv : 0);
}

/*
 * output_acl_header
 *
 * output the ACL header record and data
 */
static int
output_acl_header(sec_attr_t *acl_info,
    tlm_cmd_t *local_commands)
{
	long	actual_size;
	tlm_tar_hdr_t *tar_hdr;
	long	acl_size;

	if ((acl_info == NULL) || (*acl_info->attr_info == '\0'))
		return (0);

	tar_hdr = (tlm_tar_hdr_t *)get_write_buffer(RECORDSIZE,
	    &actual_size, TRUE, local_commands);
	if (!tar_hdr)
		return (0);

	tar_hdr->th_linkflag = LF_ACL;
	acl_info->attr_type = UFSD_ACL;
	(void) snprintf(acl_info->attr_len, sizeof (acl_info->attr_len),
	    "%06o", strlen(acl_info->attr_info));

	acl_size = sizeof (*acl_info);
	(void) strlcpy(tar_hdr->th_name, "UFSACL", TLM_NAME_SIZE);
	(void) snprintf(tar_hdr->th_size, sizeof (tar_hdr->th_size), "%011o ",
	    acl_size);
	(void) snprintf(tar_hdr->th_mode, sizeof (tar_hdr->th_mode), "%06o ",
	    0444);
	(void) snprintf(tar_hdr->th_uid, sizeof (tar_hdr->th_uid), "%06o ", 0);
	(void) snprintf(tar_hdr->th_gid, sizeof (tar_hdr->th_gid), "%06o ", 0);
	(void) snprintf(tar_hdr->th_mtime, sizeof (tar_hdr->th_mtime),
	    "%011o ", 0);
	(void) strlcpy(tar_hdr->th_magic, TLM_MAGIC,
	    sizeof (tar_hdr->th_magic));

	tlm_build_header_checksum(tar_hdr);

	(void) output_mem(local_commands, (void *)acl_info, acl_size);
	return (0);
}

/*
 * output_humongus_header
 *
 * output a special header record for HUGE files
 * output is:	1) a TAR "HUGE" header redord
 * 		2) a "file" of size, name
 */
static int
output_humongus_header(char *fullname, longlong_t file_size,
    tlm_cmd_t *local_commands)
{
	char	*buf;
	int	len;
	long	actual_size;
	tlm_tar_hdr_t *tar_hdr;

	/*
	 * buf will contain: "%llu %s":
	 * - 20 is the maximum length of 'ulong_tlong' decimal notation.
	 * - The first '1' is for the ' ' between the "%llu" and the fullname.
	 * - The last '1' is for the null-terminator of fullname.
	 */
	len = 20 + 1 + strlen(fullname) + 1;

	if ((buf = ndmp_malloc(sizeof (char) * len)) == NULL)
		return (-1);

	tar_hdr = (tlm_tar_hdr_t *)get_write_buffer(RECORDSIZE,
	    &actual_size, TRUE, local_commands);
	if (!tar_hdr) {
		free(buf);
		return (0);
	}

	tar_hdr->th_linkflag = LF_HUMONGUS;
	(void) snprintf(tar_hdr->th_size, sizeof (tar_hdr->th_size), "%011o ",
	    len);
	tlm_build_header_checksum(tar_hdr);
	(void) snprintf(buf, len, "%lld %s", file_size, fullname);
	(void) output_mem(local_commands, buf, len);

	free(buf);
	return (0);
}


/*
 * output_xattr_header
 *
 * output the TAR header record for extended attributes
 */
static int
output_xattr_header(char *fname, char *aname, int fd,
    tlm_acls_t *tlm_acls, int section, tlm_cmd_t *local_commands)
{
	struct stat64 *attr = &tlm_acls->acl_attr;
	struct xattr_hdr *xhdr;
	struct xattr_buf *xbuf;
	tlm_tar_hdr_t *tar_hdr;
	long	actual_size;
	char	*section_name = ndmp_malloc(TLM_MAX_PATH_NAME);
	int	hsize;
	int	comlen;
	int	namesz;

	if (section_name == NULL)
		return (-TLM_NO_SCRATCH_SPACE);

	if (fstat64(fd, attr) == -1) {
		NDMP_LOG(LOG_DEBUG, "output_file_header stat failed.");
		free(section_name);
		return (-TLM_OPEN_ERR);
	}

	/*
	 * if the file has to go out in sections,
	 * we must mung the name.
	 */
	if (section == 0) {
		(void) snprintf(section_name, TLM_MAX_PATH_NAME,
		    "/dev/null/%s.hdr", aname);
	} else {
		(void) snprintf(section_name,
		    TLM_MAX_PATH_NAME, "%s.%03d", aname, section);
	}
	namesz = strlen(section_name) + strlen(fname) + 2; /* 2 nulls */
	hsize = namesz + sizeof (struct xattr_hdr) + sizeof (struct xattr_buf);
	comlen = namesz + sizeof (struct xattr_buf);

	tar_hdr = (tlm_tar_hdr_t *)get_write_buffer(RECORDSIZE,
	    &actual_size, TRUE, local_commands);
	if (!tar_hdr) {
		free(section_name);
		return (0);
	}

	(void) strlcpy(tar_hdr->th_name, section_name, TLM_NAME_SIZE);

	tar_hdr->th_linkflag = LF_XATTR;
	(void) snprintf(tar_hdr->th_size, sizeof (tar_hdr->th_size), "%011o ",
	    hsize);
	(void) snprintf(tar_hdr->th_mode, sizeof (tar_hdr->th_mode), "%06o ",
	    attr->st_mode & 07777);
	(void) snprintf(tar_hdr->th_uid, sizeof (tar_hdr->th_uid), "%06o ",
	    attr->st_uid);
	(void) snprintf(tar_hdr->th_gid, sizeof (tar_hdr->th_gid), "%06o ",
	    attr->st_gid);
	(void) snprintf(tar_hdr->th_mtime, sizeof (tar_hdr->th_mtime), "%011o ",
	    attr->st_mtime);
	(void) strlcpy(tar_hdr->th_magic, TLM_MAGIC,
	    sizeof (tar_hdr->th_magic));

	NDMP_LOG(LOG_DEBUG, "xattr_hdr: %s size %d mode %06o uid %d gid %d",
	    aname, hsize, attr->st_mode & 07777, attr->st_uid, attr->st_gid);

	tlm_build_header_checksum(tar_hdr);

	xhdr = (struct xattr_hdr *)get_write_buffer(RECORDSIZE,
	    &actual_size, TRUE, local_commands);
	if (!xhdr) {
		free(section_name);
		return (0);
	}

	(void) snprintf(xhdr->h_version, sizeof (xhdr->h_version), "%s",
	    XATTR_ARCH_VERS);
	(void) snprintf(xhdr->h_size, sizeof (xhdr->h_size), "%0*d",
	    sizeof (xhdr->h_size) - 1, hsize);
	(void) snprintf(xhdr->h_component_len, sizeof (xhdr->h_component_len),
	    "%0*d", sizeof (xhdr->h_component_len) - 1, comlen);
	(void) snprintf(xhdr->h_link_component_len,
	    sizeof (xhdr->h_link_component_len), "%0*d",
	    sizeof (xhdr->h_link_component_len) - 1, 0);

	xbuf = (struct xattr_buf *)(((caddr_t)xhdr) +
	    sizeof (struct xattr_hdr));
	(void) snprintf(xbuf->h_namesz, sizeof (xbuf->h_namesz), "%0*d",
	    sizeof (xbuf->h_namesz) - 1, namesz);

	/* No support for links in extended attributes */
	xbuf->h_typeflag = LF_NORMAL;

	(void) strlcpy(xbuf->h_names, fname, TLM_NAME_SIZE);
	(void) strlcpy(&xbuf->h_names[strlen(fname) + 1], aname,
	    TLM_NAME_SIZE);

	free(section_name);
	return (0);
}


/*
 * output_file_header
 *
 * output the TAR header record
 */
static int
output_file_header(char *name, char *link,
    tlm_acls_t *tlm_acls, int section, tlm_cmd_t *local_commands)
{
	static	longlong_t file_count = 0;
	struct stat64 *attr = &tlm_acls->acl_attr;
	tlm_tar_hdr_t *tar_hdr;
	long	actual_size;
	boolean_t long_name = FALSE;
	boolean_t long_link = FALSE;
	char	*section_name = ndmp_malloc(TLM_MAX_PATH_NAME);
	int	nmlen, lnklen;
	uid_t uid;
	gid_t gid;
	char *uname = "";
	char *gname = "";
	struct passwd *pwd;
	struct group *grp;

	if (section_name == NULL)
		return (-TLM_NO_SCRATCH_SPACE);

	/*
	 * if the file has to go out in sections,
	 * we must mung the name.
	 */
	if (section == 0) {
		(void) strlcpy(section_name, name, TLM_MAX_PATH_NAME);
	} else {
		(void) snprintf(section_name,
		    TLM_MAX_PATH_NAME, "%s.%03d", name, section);
	}

	if ((pwd = getpwuid(attr->st_uid)) != NULL)
		uname = pwd->pw_name;
	if ((grp = getgrgid(attr->st_gid)) != NULL)
		gname = grp->gr_name;

	if ((ulong_t)(uid = attr->st_uid) > (ulong_t)OCTAL7CHAR)
		uid = UID_NOBODY;
	if ((ulong_t)(gid = attr->st_gid) > (ulong_t)OCTAL7CHAR)
		gid = GID_NOBODY;

	nmlen = strlen(section_name);
	if (nmlen >= NAMSIZ) {
		/*
		 * file name is too big, it must go out
		 * in its own data file
		 */
		tar_hdr = (tlm_tar_hdr_t *)get_write_buffer(RECORDSIZE,
		    &actual_size, TRUE, local_commands);
		if (!tar_hdr) {
			free(section_name);
			return (0);
		}
		(void) snprintf(tar_hdr->th_name,
		    sizeof (tar_hdr->th_name),
		    "%s%08qd.fil",
		    LONGNAME_PREFIX,
		    file_count++);

		tar_hdr->th_linkflag = LF_LONGNAME;
		(void) snprintf(tar_hdr->th_size, sizeof (tar_hdr->th_size),
		    "%011o ", nmlen);
		(void) snprintf(tar_hdr->th_mode, sizeof (tar_hdr->th_mode),
		    "%06o ", attr->st_mode & 07777);
		(void) snprintf(tar_hdr->th_uid, sizeof (tar_hdr->th_uid),
		    "%06o ", uid);
		(void) snprintf(tar_hdr->th_gid, sizeof (tar_hdr->th_gid),
		    "%06o ", gid);
		(void) snprintf(tar_hdr->th_uname, sizeof (tar_hdr->th_uname),
		    "%.31s", uname);
		(void) snprintf(tar_hdr->th_gname, sizeof (tar_hdr->th_gname),
		    "%.31s", gname);
		(void) snprintf(tar_hdr->th_mtime, sizeof (tar_hdr->th_mtime),
		    "%011o ", attr->st_mtime);
		(void) strlcpy(tar_hdr->th_magic, TLM_MAGIC,
		    sizeof (tar_hdr->th_magic));

		tlm_build_header_checksum(tar_hdr);

		(void) output_mem(local_commands,
		    (void *)section_name, nmlen);
		long_name = TRUE;
	}

	lnklen = strlen(link);
	if (lnklen >= NAMSIZ) {
		/*
		 * link name is too big, it must go out
		 * in its own data file
		 */
		tar_hdr = (tlm_tar_hdr_t *)get_write_buffer(RECORDSIZE,
		    &actual_size, TRUE, local_commands);
		if (!tar_hdr) {
			free(section_name);
			return (0);
		}
		(void) snprintf(tar_hdr->th_linkname,
		    sizeof (tar_hdr->th_name),
		    "%s%08qd.slk",
		    LONGNAME_PREFIX,
		    file_count++);

		tar_hdr->th_linkflag = LF_LONGLINK;
		(void) snprintf(tar_hdr->th_size, sizeof (tar_hdr->th_size),
		    "%011o ", lnklen);
		(void) snprintf(tar_hdr->th_mode, sizeof (tar_hdr->th_mode),
		    "%06o ", attr->st_mode & 07777);
		(void) snprintf(tar_hdr->th_uid, sizeof (tar_hdr->th_uid),
		    "%06o ", uid);
		(void) snprintf(tar_hdr->th_gid, sizeof (tar_hdr->th_gid),
		    "%06o ", gid);
		(void) snprintf(tar_hdr->th_uname, sizeof (tar_hdr->th_uname),
		    "%.31s", uname);
		(void) snprintf(tar_hdr->th_gname, sizeof (tar_hdr->th_gname),
		    "%.31s", gname);
		(void) snprintf(tar_hdr->th_mtime, sizeof (tar_hdr->th_mtime),
		    "%011o ", attr->st_mtime);
		(void) strlcpy(tar_hdr->th_magic, TLM_MAGIC,
		    sizeof (tar_hdr->th_magic));

		tlm_build_header_checksum(tar_hdr);

		(void) output_mem(local_commands, (void *)link,
		    lnklen);
		long_link = TRUE;
	}
	tar_hdr = (tlm_tar_hdr_t *)get_write_buffer(RECORDSIZE,
	    &actual_size, TRUE, local_commands);
	if (!tar_hdr) {
		free(section_name);
		return (0);
	}
	if (long_name) {
		(void) snprintf(tar_hdr->th_name,
		    sizeof (tar_hdr->th_name),
		    "%s%08qd.fil",
		    LONGNAME_PREFIX,
		    file_count++);
	} else {
		(void) strlcpy(tar_hdr->th_name, section_name, TLM_NAME_SIZE);
	}

	NDMP_LOG(LOG_DEBUG, "long_link: %s [%s]", long_link ? "TRUE" : "FALSE",
	    link);

	if (long_link) {
		(void) snprintf(tar_hdr->th_linkname,
		    sizeof (tar_hdr->th_name),
		    "%s%08qd.slk",
		    LONGNAME_PREFIX,
		    file_count++);
	} else {
		(void) strlcpy(tar_hdr->th_linkname, link, TLM_NAME_SIZE);
	}
	switch (attr->st_mode & S_IFMT) {
	case S_IFDIR:
		tar_hdr->th_linkflag = LF_DIR;
		break;
	case S_IFIFO:
		tar_hdr->th_linkflag = LF_FIFO;
		break;
	case S_IFBLK:
	case S_IFCHR:
		if (S_ISBLK(attr->st_mode))
			tar_hdr->th_linkflag = LF_BLK;
		else
			tar_hdr->th_linkflag = LF_CHR;
		(void) snprintf(tar_hdr->th_shared.th_dev.th_devmajor,
		    sizeof (tar_hdr->th_shared.th_dev.th_devmajor), "%06o ",
		    major(attr->st_rdev));
		(void) snprintf(tar_hdr->th_shared.th_dev.th_devminor,
		    sizeof (tar_hdr->th_shared.th_dev.th_devminor), "%06o ",
		    minor(attr->st_rdev));
		break;
	default:
		if (attr->st_nlink > 1) {
			/* mark file with hardlink LF_LINK */
			tar_hdr->th_linkflag = LF_LINK;
			(void) snprintf(tar_hdr->th_shared.th_hlink_ino,
			    sizeof (tar_hdr->th_shared.th_hlink_ino),
			    "%011llo ", attr->st_ino);
		} else {
			tar_hdr->th_linkflag = *link == 0 ? LF_NORMAL :
			    LF_SYMLINK;
			NDMP_LOG(LOG_DEBUG, "linkflag: '%c'",
			    tar_hdr->th_linkflag);
		}
	}
	(void) snprintf(tar_hdr->th_size, sizeof (tar_hdr->th_size), "%011o ",
	    (long)attr->st_size);
	(void) snprintf(tar_hdr->th_mode, sizeof (tar_hdr->th_mode), "%06o ",
	    attr->st_mode & 07777);
	(void) snprintf(tar_hdr->th_uid, sizeof (tar_hdr->th_uid), "%06o ",
	    uid);
	(void) snprintf(tar_hdr->th_gid, sizeof (tar_hdr->th_gid), "%06o ",
	    gid);
	(void) snprintf(tar_hdr->th_uname, sizeof (tar_hdr->th_uname), "%.31s",
	    uname);
	(void) snprintf(tar_hdr->th_gname, sizeof (tar_hdr->th_gname), "%.31s",
	    gname);
	(void) snprintf(tar_hdr->th_mtime, sizeof (tar_hdr->th_mtime), "%011o ",
	    attr->st_mtime);
	(void) strlcpy(tar_hdr->th_magic, TLM_MAGIC,
	    sizeof (tar_hdr->th_magic));

	tlm_build_header_checksum(tar_hdr);
	if (long_name || long_link) {
		if (file_count > 99999990) {
			file_count = 0;
		}
	}
	free(section_name);
	return (0);
}


/*
 * tlm_readlink
 *
 * Read where the softlink points to.  Read the link in the checkpointed
 * path if the backup is being done on a checkpointed file system.
 */
static int
tlm_readlink(char *nm, char *snap, char *buf, int bufsize)
{
	int len;

	if ((len = readlink(snap, buf, bufsize)) >= 0) {
		/*
		 * realink(2) doesn't null terminate the link name.  We must
		 * do it here.
		 */
		buf[len] = '\0';
	} else {
		NDMP_LOG(LOG_DEBUG, "Error %d reading softlink of [%s]",
		    errno, nm);
		buf[0] = '\0';

		/* Backup the link if the destination missing */
		if (errno == ENOENT)
			return (0);

	}

	return (len);
}

/*
 * Read the system attribute file in a single buffer to write
 * it as a single write. A partial write to system attribute would
 * cause an EINVAL on write.
 */
static char *
get_write_one_buf(char *buf, char *rec, int buf_size, int rec_size,
    tlm_cmd_t *lc)
{
	int len;
	long write_size;

	if (rec_size > buf_size)
		return (rec);

	len = rec_size;
	(void) memcpy(rec, buf, len);
	buf += len;
	while (rec_size < buf_size) {
		rec = get_write_buffer(buf_size - rec_size,
		    &write_size, FALSE, lc);
		if (!rec)
			return (0);

		len = min(buf_size - rec_size, write_size);
		(void) memcpy(rec, buf, len);
		rec_size += len;
		buf += len;
	}
	return (rec);
}


/*
 * tlm_output_xattr
 *
 * Put this file into the output buffers.
 */
/*ARGSUSED*/
longlong_t
tlm_output_xattr(char  *dir, char *name, char *chkdir,
    tlm_acls_t *tlm_acls, tlm_commands_t *commands,
    tlm_cmd_t *local_commands, tlm_job_stats_t *job_stats)
{
	char	*fullname;		/* directory + name */
	char	*snapname;		/* snapshot name */
	int	section;		/* section of a huge file */
	int	fd;
	int	afd = 0;
	longlong_t seek_spot = 0;	/* location in the file */
					/* for Multi Volume record */
	u_longlong_t pos;
	DIR *dp;
	struct dirent *dtp;
	char *attrname;
	char *fnamep;
	int rv = 0;

	if (S_ISPECIAL(tlm_acls->acl_attr.st_mode)) {
		return (TLM_NO_SOURCE_FILE);
	}

	fullname = ndmp_malloc(TLM_MAX_PATH_NAME);
	if (fullname == NULL) {
		free(fullname);
		return (-TLM_NO_SCRATCH_SPACE);
	}

	if (!tlm_cat_path(fullname, dir, name)) {
		NDMP_LOG(LOG_DEBUG, "Path too long.");
		free(fullname);
		return (-TLM_NO_SCRATCH_SPACE);
	}

	if (pathconf(fullname, _PC_XATTR_EXISTS) != 1 &&
	    sysattr_support(fullname, _PC_SATTR_EXISTS) != 1) {
		free(fullname);
		return (0);
	}

	attrname = ndmp_malloc(TLM_MAX_PATH_NAME);
	snapname = ndmp_malloc(TLM_MAX_PATH_NAME);
	if (attrname == NULL || snapname == NULL) {
		rv = -TLM_NO_SCRATCH_SPACE;
		goto err_out;
	}

	if (!tlm_cat_path(snapname, chkdir, name)) {
		NDMP_LOG(LOG_DEBUG, "Path too long.");
		rv = -TLM_NO_SCRATCH_SPACE;
		goto err_out;
	}

	fnamep = (tlm_acls->acl_checkpointed) ? snapname : fullname;

	/*
	 * Open the file for reading.
	 */
	fd = attropen(fnamep, ".", O_RDONLY);
	if (fd == -1) {
		NDMP_LOG(LOG_DEBUG, "BACKUP> Can't open file [%s][%s]",
		    fullname, fnamep);
		rv = TLM_NO_SOURCE_FILE;
		goto err_out;
	}

	pos = tlm_get_data_offset(local_commands);
	NDMP_LOG(LOG_DEBUG, "pos: %10lld  [%s]", pos, name);

	section = 0;

	dp = (DIR *)fdopendir(fd);
	if (dp == NULL) {
		NDMP_LOG(LOG_DEBUG, "BACKUP> Can't open file [%s]", fullname);
		(void) close(fd);
		rv = TLM_NO_SOURCE_FILE;
		goto err_out;
	}

	while ((dtp = readdir(dp)) != NULL) {
		int section_size;

		if (*dtp->d_name == '.')
			continue;

		if (sysattr_rdonly(dtp->d_name))
			continue;

		afd = attropen(fnamep, dtp->d_name, O_RDONLY);
		if (afd == -1) {
			NDMP_LOG(LOG_DEBUG,
			    "problem(%d) opening xattr file [%s][%s]", errno,
			    fullname, fnamep);
			goto tear_down;
		}

		(void) output_xattr_header(fullname, dtp->d_name, afd,
		    tlm_acls, section, local_commands);
		(void) snprintf(attrname, TLM_MAX_PATH_NAME, "/dev/null/%s",
		    dtp->d_name);
		(void) output_file_header(attrname, "", tlm_acls, 0,
		    local_commands);

		section_size = (long)llmin(tlm_acls->acl_attr.st_size,
		    (longlong_t)TLM_MAX_TAR_IMAGE);

		/* We only can read upto one section extended attribute */
		while (section_size > 0) {
			char	*buf;
			long	actual_size;
			int	read_size;
			int sysattr_read = 0;
			char *rec;
			int size;

			/*
			 * check for Abort commands
			 */
			if (commands->tcs_reader != TLM_BACKUP_RUN) {
				local_commands->tc_writer = TLM_ABORT;
				goto tear_down;
			}

			local_commands->tc_buffers->tbs_buffer[
			    local_commands->tc_buffers->tbs_buffer_in].
			    tb_file_size = section_size;
			local_commands->tc_buffers->tbs_buffer[
			    local_commands->tc_buffers->tbs_buffer_in].
			    tb_seek_spot = seek_spot;

			buf = get_write_buffer(section_size,
			    &actual_size, FALSE, local_commands);
			if (!buf)
				goto tear_down;

			if ((actual_size < section_size) &&
			    sysattr_rw(dtp->d_name)) {
				rec = buf;
				buf = ndmp_malloc(section_size);
				if (!buf)
					goto tear_down;
				size = actual_size;
				actual_size = section_size;
				sysattr_read = 1;
			}

			/*
			 * check for Abort commands
			 */
			if (commands->tcs_reader != TLM_BACKUP_RUN) {
				local_commands->tc_writer = TLM_ABORT;
				goto tear_down;
			}

			read_size = min(section_size, actual_size);
			if ((actual_size = read(afd, buf, read_size)) < 0)
				break;

			if (sysattr_read) {
				if (get_write_one_buf(buf, rec, read_size,
				    size, local_commands) == 0) {
					free(buf);
					goto tear_down;
				}
				free(buf);
			}


			NS_ADD(rdisk, actual_size);
			NS_INC(rfile);

			if (actual_size == -1) {
				NDMP_LOG(LOG_DEBUG,
				    "problem(%d) reading file [%s][%s]",
				    errno, fullname, snapname);
				goto tear_down;
			}
			seek_spot += actual_size;
			section_size -= actual_size;
		}
		(void) close(afd);
		afd = -1;
	}

tear_down:
	local_commands->tc_buffers->tbs_buffer[
	    local_commands->tc_buffers->tbs_buffer_in].tb_seek_spot = 0;

	if (afd > 0)
		(void) close(afd);

	/* closedir closes fd too */
	(void) closedir(dp);

err_out:
	free(fullname);
	free(attrname);
	free(snapname);
	return (rv);
}


/*
 * tlm_output_file
 *
 * Put this file into the output buffers.
 */
longlong_t
tlm_output_file(char *dir, char *name, char *chkdir,
    tlm_acls_t *tlm_acls, tlm_commands_t *commands, tlm_cmd_t *local_commands,
    tlm_job_stats_t *job_stats, struct hardlink_q *hardlink_q)
{
	char	*fullname;		/* directory + name */
	char	*snapname;		/* snapshot name */
	char	*linkname;		/* where this file points */
	int	section = 0;		/* section of a huge file */
	int	fd;
	longlong_t real_size;		/* the origional file size */
	longlong_t file_size;		/* real size of this file */
	longlong_t seek_spot = 0;	/* location in the file */
					/* for Multi Volume record */
	u_longlong_t pos;
	char *fnamep;

	/* Indicate whether a file with the same inode has been backed up. */
	int hardlink_done = 0;

	/*
	 * If a file with the same inode has been backed up, hardlink_pos holds
	 * the tape offset of the data record.
	 */
	u_longlong_t hardlink_pos = 0;

	if (tlm_is_too_long(tlm_acls->acl_checkpointed, dir, name)) {
		NDMP_LOG(LOG_DEBUG, "Path too long [%s][%s]", dir, name);
		return (-TLM_NO_SCRATCH_SPACE);
	}

	fullname = ndmp_malloc(TLM_MAX_PATH_NAME);
	linkname = ndmp_malloc(TLM_MAX_PATH_NAME);
	snapname = ndmp_malloc(TLM_MAX_PATH_NAME);
	if (fullname == NULL || linkname == NULL || snapname == NULL) {
		real_size = -TLM_NO_SCRATCH_SPACE;
		goto err_out;
	}
	if (!tlm_cat_path(fullname, dir, name) ||
	    !tlm_cat_path(snapname, chkdir, name)) {
		NDMP_LOG(LOG_DEBUG, "Path too long.");
		real_size = -TLM_NO_SCRATCH_SPACE;
		goto err_out;
	}

	pos = tlm_get_data_offset(local_commands);
	NDMP_LOG(LOG_DEBUG, "pos: %10lld  [%s]", pos, name);

	if (S_ISPECIAL(tlm_acls->acl_attr.st_mode)) {
		if (S_ISLNK(tlm_acls->acl_attr.st_mode)) {
			file_size = tlm_readlink(fullname, snapname, linkname,
			    TLM_MAX_PATH_NAME-1);
			if (file_size < 0) {
				real_size = -ENOENT;
				goto err_out;
			}
		}

		/*
		 * Since soft links can not be read(2), we should only
		 * backup the file header.
		 */
		(void) output_file_header(fullname,
		    linkname,
		    tlm_acls,
		    section,
		    local_commands);

		(void) tlm_log_fhnode(job_stats, dir, name,
		    &tlm_acls->acl_attr, pos);
		(void) tlm_log_fhpath_name(job_stats, fullname,
		    &tlm_acls->acl_attr, pos);

		free(fullname);
		free(linkname);
		free(snapname);
		return (0);
	}

	fnamep = (tlm_acls->acl_checkpointed) ? snapname : fullname;

	/*
	 * For hardlink, only read the data if no other link
	 * belonging to the same inode has been backed up.
	 */
	if (tlm_acls->acl_attr.st_nlink > 1) {
		hardlink_done = !hardlink_q_get(hardlink_q,
		    tlm_acls->acl_attr.st_ino, &hardlink_pos, NULL);
	}

	if (!hardlink_done) {
		/*
		 * Open the file for reading.
		 */
		fd = open(fnamep, O_RDONLY);
		if (fd == -1) {
			NDMP_LOG(LOG_DEBUG,
			    "BACKUP> Can't open file [%s][%s] err(%d)",
			    fullname, fnamep, errno);
			real_size = -TLM_NO_SOURCE_FILE;
			goto err_out;
		}
	} else {
		NDMP_LOG(LOG_DEBUG, "found hardlink, inode = %llu, pos = %llu ",
		    tlm_acls->acl_attr.st_ino, hardlink_pos);

		fd = -1;
	}

	linkname[0] = 0;

	real_size = tlm_acls->acl_attr.st_size;
	(void) output_acl_header(&tlm_acls->acl_info,
	    local_commands);

	/*
	 * section = 0: file is small enough for TAR
	 * section > 0: file goes out in TLM_MAX_TAR_IMAGE sized chunks
	 * 		and the file name gets munged
	 */
	file_size = real_size;
	if (file_size > TLM_MAX_TAR_IMAGE) {
		if (output_humongus_header(fullname, file_size,
		    local_commands) < 0) {
			(void) close(fd);
			real_size = -TLM_NO_SCRATCH_SPACE;
			goto err_out;
		}
		section = 1;
	} else {
		section = 0;
	}

	/*
	 * For hardlink, if other link belonging to the same inode
	 * has been backed up, only backup an empty record.
	 */
	if (hardlink_done)
		file_size = 0;

	/*
	 * work
	 */
	if (file_size == 0) {
		(void) output_file_header(fullname,
		    linkname,
		    tlm_acls,
		    section,
		    local_commands);
		/*
		 * this can fall right through since zero size files
		 * will be skipped by the WHILE loop anyway
		 */
	}

	while (file_size > 0) {
		int section_size = llmin(file_size,
		    (longlong_t)TLM_MAX_TAR_IMAGE);

		tlm_acls->acl_attr.st_size = (longlong_t)section_size;
		(void) output_file_header(fullname,
		    linkname,
		    tlm_acls,
		    section,
		    local_commands);
		while (section_size > 0) {
			char	*buf;
			long	actual_size;
			int	read_size;

			/*
			 * check for Abort commands
			 */
			if (commands->tcs_reader != TLM_BACKUP_RUN) {
				local_commands->tc_writer = TLM_ABORT;
				goto tear_down;
			}

			local_commands->tc_buffers->tbs_buffer[
			    local_commands->tc_buffers->tbs_buffer_in].
			    tb_file_size = section_size;
			local_commands->tc_buffers->tbs_buffer[
			    local_commands->tc_buffers->tbs_buffer_in].
			    tb_seek_spot = seek_spot;

			buf = get_write_buffer(section_size,
			    &actual_size, FALSE, local_commands);
			if (!buf)
				goto tear_down;

			/*
			 * check for Abort commands
			 */
			if (commands->tcs_reader != TLM_BACKUP_RUN) {
				local_commands->tc_writer = TLM_ABORT;
				goto tear_down;
			}

			read_size = min(section_size, actual_size);
			actual_size = read(fd, buf, read_size);
			NS_ADD(rdisk, actual_size);
			NS_INC(rfile);

			if (actual_size == 0)
				break;

			if (actual_size == -1) {
				NDMP_LOG(LOG_DEBUG,
				    "problem(%d) reading file [%s][%s]",
				    errno, fullname, snapname);
				goto tear_down;
			}
			seek_spot += actual_size;
			file_size -= actual_size;
			section_size -= actual_size;
		}
		section++;
	}

	/*
	 * If data belonging to this hardlink has been backed up, add the link
	 * to hardlink queue.
	 */
	if (tlm_acls->acl_attr.st_nlink > 1 && !hardlink_done) {
		(void) hardlink_q_add(hardlink_q, tlm_acls->acl_attr.st_ino,
		    pos, NULL, 0);
		NDMP_LOG(LOG_DEBUG,
		    "backed up hardlink file %s, inode = %llu, pos = %llu ",
		    fullname, tlm_acls->acl_attr.st_ino, pos);
	}

	/*
	 * For hardlink, if other link belonging to the same inode has been
	 * backed up, no add_node entry should be sent for this link.
	 */
	if (hardlink_done) {
		NDMP_LOG(LOG_DEBUG,
		    "backed up hardlink link %s, inode = %llu, pos = %llu ",
		    fullname, tlm_acls->acl_attr.st_ino, hardlink_pos);
	} else {
		(void) tlm_log_fhnode(job_stats, dir, name,
		    &tlm_acls->acl_attr, pos);
	}

	(void) tlm_log_fhpath_name(job_stats, fullname, &tlm_acls->acl_attr,
	    pos);

tear_down:
	local_commands->tc_buffers->tbs_buffer[
	    local_commands->tc_buffers->tbs_buffer_in].tb_seek_spot = 0;

	(void) close(fd);

err_out:
	free(fullname);
	free(linkname);
	free(snapname);
	return (real_size);
}

/*
 * tar_putfile
 *
 * Main file backup function for tar
 */
int
tar_putfile(char *dir, char *name, char *chkdir,
    tlm_acls_t *tlm_acls, tlm_commands_t *commands,
    tlm_cmd_t *local_commands, tlm_job_stats_t *job_stats,
    struct hardlink_q *hardlink_q)
{
	int rv;

	rv = tlm_output_file(dir, name, chkdir, tlm_acls, commands,
	    local_commands, job_stats, hardlink_q);
	if (rv < 0)
		return (rv);

	rv = tlm_output_xattr(dir, name, chkdir, tlm_acls, commands,
	    local_commands, job_stats);

	return (rv < 0 ? rv : 0);
}

/*
 * get_write_buffer
 *
 * a wrapper to tlm_get_write_buffer so that
 * we can cleanly detect ABORT commands
 * without involving the TLM library with
 * our problems.
 */
static char *
get_write_buffer(long size, long *actual_size,
    boolean_t zero, tlm_cmd_t *local_commands)
{
	while (local_commands->tc_reader == TLM_BACKUP_RUN) {
		char *rec = tlm_get_write_buffer(size, actual_size,
		    local_commands->tc_buffers, zero);
		if (rec != 0) {
			return (rec);
		}
	}
	return (NULL);
}

#define	NDMP_MORE_RECORDS	2

/*
 * write_tar_eof
 *
 * This function is initially written for NDMP support.  It appends
 * two tar headers to the tar file, and also N more empty buffers
 * to make sure that the two tar headers will be read as a part of
 * a mover record and don't get locked because of EOM on the mover
 * side.
 */
void
write_tar_eof(tlm_cmd_t *local_commands)
{
	int i;
	long actual_size;
	tlm_buffers_t *bufs;

	/*
	 * output 2 zero filled records,
	 * TAR wants this.
	 */
	(void) get_write_buffer(sizeof (tlm_tar_hdr_t),
	    &actual_size, TRUE, local_commands);
	(void) get_write_buffer(sizeof (tlm_tar_hdr_t),
	    &actual_size, TRUE, local_commands);

	/*
	 * NDMP: Clear the rest of the buffer and write two more buffers
	 * to the tape.
	 */
	bufs = local_commands->tc_buffers;
	(void) get_write_buffer(bufs->tbs_data_transfer_size,
	    &actual_size, TRUE, local_commands);

	for (i = 0; i < NDMP_MORE_RECORDS &&
	    local_commands->tc_reader == TLM_BACKUP_RUN; i++) {
		/*
		 * We don't need the return value of get_write_buffer(),
		 * since it's already zeroed out if the buffer is returned.
		 */
		(void) get_write_buffer(bufs->tbs_data_transfer_size,
		    &actual_size, TRUE, local_commands);
	}

	bufs->tbs_buffer[bufs->tbs_buffer_in].tb_full = TRUE;
	tlm_buffer_release_in_buf(bufs);
}

/*
 * Callback to backup each ZFS property
 */
static int
zfs_put_prop_cb(int prop, void *pp)
{
	ndmp_metadata_handle_t *mhd;
	ndmp_metadata_header_ext_t *mhp;
	ndmp_metadata_property_ext_t *mpp;
	char vbuf[ZFS_MAXPROPLEN];
	char sbuf[ZFS_MAXPROPLEN];
	zprop_source_t stype;
	char *sourcestr;

	if (pp == NULL)
		return (ZPROP_INVAL);

	mhd = (ndmp_metadata_handle_t *)pp;
	mhp = mhd->ml_xhdr;
	mpp = &mhp->nh_property[mhp->nh_count];

	if (mhp->nh_count * sizeof (ndmp_metadata_property_ext_t) +
	    sizeof (ndmp_metadata_header_ext_t) > mhp->nh_total_bytes)
		return (ZPROP_INVAL);

	if (zfs_prop_get(mhd->ml_handle, prop, vbuf, sizeof (vbuf),
	    &stype, sbuf, sizeof (sbuf), B_TRUE) != 0) {
		mhp->nh_count++;
		return (ZPROP_CONT);
	}

	(void) strlcpy(mpp->mp_name, zfs_prop_to_name(prop), ZFS_MAXNAMELEN);
	(void) strlcpy(mpp->mp_value, vbuf, ZFS_MAXPROPLEN);

	switch (stype) {
	case ZPROP_SRC_NONE:
		sourcestr = "none";
		break;
	case ZPROP_SRC_RECEIVED:
		sourcestr = "received";
		break;
	case ZPROP_SRC_LOCAL:
		sourcestr = mhp->nh_dataset;
		break;
	case ZPROP_SRC_TEMPORARY:
		sourcestr = "temporary";
		break;
	case ZPROP_SRC_DEFAULT:
		sourcestr = "default";
		break;
	default:
		sourcestr = sbuf;
		break;
	}
	(void) strlcpy(mpp->mp_source, sourcestr, ZFS_MAXPROPLEN);

	mhp->nh_count++;
	return (ZPROP_CONT);
}

/*
 * Callback to backup each ZFS user/group quota
 */
static int
zfs_put_quota_cb(void *pp, const char *domain, uid_t rid, uint64_t space)
{
	ndmp_metadata_handle_t *mhd;
	ndmp_metadata_header_ext_t *mhp;
	ndmp_metadata_property_ext_t *mpp;
	char *typestr;

	if (pp == NULL)
		return (ZPROP_INVAL);

	mhd = (ndmp_metadata_handle_t *)pp;
	mhp = mhd->ml_xhdr;
	mpp = &mhp->nh_property[mhp->nh_count];

	if (mhp->nh_count * sizeof (ndmp_metadata_property_ext_t) +
	    sizeof (ndmp_metadata_header_ext_t) > mhp->nh_total_bytes)
		return (ZPROP_INVAL);

	if (mhd->ml_quota_prop == ZFS_PROP_USERQUOTA)
		typestr = "userquota";
	else
		typestr = "groupquota";

	if (domain == NULL || *domain == '\0')
		(void) snprintf(mpp->mp_name, ZFS_MAXNAMELEN, "%s@%llu",
		    typestr, (longlong_t)rid);
	else
		(void) snprintf(mpp->mp_name, ZFS_MAXNAMELEN, "%s@%s-%llu",
		    typestr, domain, (longlong_t)rid);
	(void) snprintf(mpp->mp_value, ZFS_MAXPROPLEN, "%llu", space);
	(void) strlcpy(mpp->mp_source, mhp->nh_dataset, ZFS_MAXPROPLEN);

	mhp->nh_count++;
	return (0);
}

/*
 * Callback to count each ZFS property
 */
/*ARGSUSED*/
static int
zfs_count_prop_cb(int prop, void *pp)
{
	(*(int *)pp)++;
	return (ZPROP_CONT);
}

/*
 * Callback to count each ZFS user/group quota
 */
/*ARGSUSED*/
static int
zfs_count_quota_cb(void *pp, const char *domain, uid_t rid, uint64_t space)
{
	(*(int *)pp)++;
	return (0);
}

/*
 * Count the number of ZFS properties and user/group quotas
 */
int
zfs_get_prop_counts(zfs_handle_t *zhp)
{
	int count = 0;
	nvlist_t *uprops;
	nvpair_t *elp;

	if (zhp == NULL)
		return (0);

	(void) zprop_iter(zfs_count_prop_cb, &count, TRUE, TRUE,
	    ZFS_TYPE_VOLUME | ZFS_TYPE_DATASET);

	(void) zfs_userspace(zhp, ZFS_PROP_USERQUOTA, zfs_count_quota_cb,
	    &count);
	(void) zfs_userspace(zhp, ZFS_PROP_GROUPQUOTA, zfs_count_quota_cb,
	    &count);

	uprops = zfs_get_user_props(zhp);

	elp = nvlist_next_nvpair(uprops, NULL);
	for (; elp != NULL; elp = nvlist_next_nvpair(uprops, elp))
		count++;

	return (count);
}

/*
 * Notifies ndmpd that the metadata associated with the given ZFS dataset
 * should be backed up.
 */
int
ndmp_include_zfs(ndmp_context_t *nctx, const char *dataset)
{
	tlm_commands_t *cmds;
	ndmp_metadata_handle_t mhd;
	ndmp_metadata_header_ext_t *mhp;
	ndmp_metadata_property_ext_t *mpp;
	zfs_handle_t *zhp;
	tlm_cmd_t *lcmd;
	long actual_size;
	nvlist_t *uprops, *ulist;
	const char *pname;
	nvpair_t *elp;
	char *sval, *ssrc;
	char *wbuf, *pp, *tp;
	long size, lsize, sz;
	int align = RECORDSIZE - 1;
	int pcount;

	if (nctx == NULL || (cmds = (tlm_commands_t *)nctx->nc_cmds) == NULL)
		return (-1);

	if ((lcmd = cmds->tcs_command) == NULL ||
	    lcmd->tc_buffers == NULL)
		return (-1);

	(void) mutex_lock(&zlib_mtx);
	if ((zhp = zfs_open(zlibh, dataset, ZFS_TYPE_DATASET)) == NULL) {
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	pcount = zfs_get_prop_counts(zhp);
	size = sizeof (ndmp_metadata_header_ext_t) +
	    pcount * sizeof (ndmp_metadata_property_ext_t);

	size += align;
	size &= ~align;

	if ((mhp = malloc(size)) == NULL) {
		zfs_close(zhp);
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	(void) memset(mhp, 0, size);

	mhd.ml_handle = zhp;
	mhd.ml_xhdr = mhp;
	mhp->nh_total_bytes = size;
	mhp->nh_major = META_HDR_MAJOR_VERSION;
	mhp->nh_minor = META_HDR_MINOR_VERSION;
	mhp->nh_plversion = nctx->nc_plversion;

	(void) strlcpy(mhp->nh_plname, nctx->nc_plname,
	    sizeof (mhp->nh_plname));
	(void) strlcpy(mhp->nh_magic, ZFS_META_MAGIC_EXT,
	    sizeof (mhp->nh_magic));
	(void) strlcpy(mhp->nh_dataset, dataset, sizeof (mhp->nh_dataset));

	/* Get all the ZFS properties */
	(void) zprop_iter(zfs_put_prop_cb, &mhd, TRUE, TRUE,
	    ZFS_TYPE_VOLUME | ZFS_TYPE_DATASET);

	/* Get user properties */
	uprops = zfs_get_user_props(mhd.ml_handle);

	elp = nvlist_next_nvpair(uprops, NULL);

	while (elp != NULL) {
		mpp = &mhp->nh_property[mhp->nh_count];
		if (nvpair_value_nvlist(elp, &ulist) != 0 ||
		    nvlist_lookup_string(ulist, ZPROP_VALUE, &sval) != 0 ||
		    nvlist_lookup_string(ulist, ZPROP_SOURCE, &ssrc) != 0) {
			zfs_close(mhd.ml_handle);
			(void) mutex_unlock(&zlib_mtx);
			free(mhp);
			return (-1);
		}
		if ((pname = nvpair_name(elp)) != NULL)
			(void) strlcpy(mpp->mp_name, pname, ZFS_MAXNAMELEN);

		(void) strlcpy(mpp->mp_value, sval, ZFS_MAXPROPLEN);
		(void) strlcpy(mpp->mp_source, ssrc, ZFS_MAXPROPLEN);
		mhp->nh_count++;
		elp = nvlist_next_nvpair(uprops, elp);
	}

	mhd.ml_quota_prop = ZFS_PROP_USERQUOTA;
	(void) zfs_userspace(mhd.ml_handle, ZFS_PROP_USERQUOTA,
	    zfs_put_quota_cb, &mhd);
	mhd.ml_quota_prop = ZFS_PROP_GROUPQUOTA;
	(void) zfs_userspace(mhd.ml_handle, ZFS_PROP_GROUPQUOTA,
	    zfs_put_quota_cb, &mhd);
	mhp->nh_count = pcount;

	zfs_close(mhd.ml_handle);
	(void) mutex_unlock(&zlib_mtx);

	if ((wbuf = get_write_buffer(size, &actual_size, TRUE,
	    lcmd)) != NULL) {
		pp = (char *)mhp;

		(void) memcpy(wbuf, pp, (actual_size < size) ?
		    actual_size : size);
		pp += (actual_size < size) ? actual_size : size;

		sz = actual_size;
		while (sz < size &&
		    ((tp = get_write_buffer(size - sz, &lsize,
		    TRUE, lcmd))) != NULL) {
			(void) memcpy(tp, pp, lsize);
			sz += lsize;
			pp += lsize;
		}
		if (sz > size) {
			tlm_unget_write_buffer(lcmd->tc_buffers, sz - size);
		}
	}

	free(mhp);
	return (0);
}
