/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/note.h>
#include <sys/t_lock.h>
#include <sys/cmn_err.h>
#include <sys/instance.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/hwconf.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/modctl.h>
#include <sys/dacf.h>
#include <sys/promif.h>
#include <sys/cpuvar.h>
#include <sys/pathname.h>
#include <sys/taskq.h>
#include <sys/sysevent.h>
#include <sys/sunmdi.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/fs/snode.h>
#include <sys/fs/dv_node.h>
#include <sys/kobj.h>

#include <sys/devctl_impl.h>


/*
 * Tunables - see devctl_impl.h for more thorough explanation
 */
int devid_discovery_boot = 1;
int devid_discovery_postboot = 1;
int devid_discovery_postboot_always = 0;
int devid_discovery_secs = 0;

int devid_cache_read_disable = 0;
int devid_cache_write_disable = 0;

int kfio_report_error = 0;		/* kernel file i/o operations */
int devid_report_error = 0;		/* devid cache operations */


/*
 * State to manage discovery
 */
static int		devid_discovery_busy = 0;
static kmutex_t		devid_discovery_mutex;
static kcondvar_t	devid_discovery_cv;
static clock_t		devid_last_discovery = 0;

/*
 * Descriptor for /etc/devices/devid_cache
 */
nvfd_t devid_cache_fd = {
	"/etc/devices/devid_cache",
};
static nvfd_t *dcfd = &devid_cache_fd;


extern int modrootloaded;
extern struct bootops *bootops;

#ifdef	DEBUG
int nvp_devid_debug = 0;
int nvpdaemon_debug = 0;
int kfio_debug = 0;
int devid_debug = 0;
int devid_log_registers = 0;
int devid_log_finds = 0;
int devid_log_lookups = 0;
int devid_log_discovery = 0;
int devid_log_matches = 0;
int devid_log_paths = 0;
int devid_log_failures = 0;
int devid_log_hold = 0;
int devid_log_unregisters = 0;
int devid_log_removes = 0;
int devid_register_debug = 0;
int devid_log_stale = 0;
int devid_log_detaches = 0;
#endif	/* DEBUG */


void
i_ddi_devices_init(void)
{
	dcfd->nvf_flags = 0;
	dcfd->nvf_list = NULL;
	dcfd->nvf_tail = NULL;
	rw_init(&dcfd->nvf_lock, NULL, RW_DRIVER, NULL);

	mutex_init(&devid_discovery_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&devid_discovery_cv, NULL, CV_DRIVER, NULL);
}

static uint16_t
nvp_cksum(uchar_t *buf, int64_t buflen)
{
	uint16_t cksum = 0;
	uint16_t *p = (uint16_t *)buf;
	int64_t n;

	if ((buflen & 0x01) != 0) {
		buflen--;
		cksum = buf[buflen];
	}
	n = buflen / 2;
	while (n-- > 0)
		cksum ^= *p++;
	return (cksum);
}

static int
fread_nvlist(char *filename, nvlist_t **ret_nvlist)
{
	struct _buf	*file;
	nvpf_hdr_t	hdr;
	char		*buf;
	nvlist_t	*nvl;
	int		rval;
	uint_t		offset;
	int		n;
	char		c;
	uint16_t	cksum, hdrsum;

	*ret_nvlist = NULL;

	file = kobj_open_file(filename);
	if (file == (struct _buf *)-1) {
		KFDEBUG((CE_CONT, "cannot open file: %s\n", filename));
		return (ENOENT);
	}

	offset = 0;
	n = kobj_read_file(file, (char *)&hdr, sizeof (hdr), offset);
	if (n != sizeof (hdr)) {
		kobj_close_file(file);
		if (n < 0) {
			KFIOERR((CE_CONT,
			    "error reading header: %s\n", filename));
			return (EIO);
		} else if (n == 0) {
			KFDEBUG((CE_CONT, "file empty: %s\n", filename));
		} else {
			KFIOERR((CE_CONT,
				"header size incorrect: %s\n", filename));
		}
		return (EINVAL);
	}
	offset += n;

	KFDEBUG2((CE_CONT, "nvpf_magic: 0x%x\n", hdr.nvpf_magic));
	KFDEBUG2((CE_CONT, "nvpf_version: %d\n", hdr.nvpf_version));
	KFDEBUG2((CE_CONT, "nvpf_size: %lld\n",
		(longlong_t)hdr.nvpf_size));
	KFDEBUG2((CE_CONT, "nvpf_hdr_chksum: 0x%x\n",
		hdr.nvpf_hdr_chksum));
	KFDEBUG2((CE_CONT, "nvpf_chksum: 0x%x\n", hdr.nvpf_chksum));

	cksum = hdr.nvpf_hdr_chksum;
	hdr.nvpf_hdr_chksum = 0;
	hdrsum = nvp_cksum((uchar_t *)&hdr, sizeof (hdr));

	if (hdr.nvpf_magic != NVPF_HDR_MAGIC ||
	    hdr.nvpf_version != NVPF_HDR_VERSION || hdrsum != cksum) {
		kobj_close_file(file);
		if (hdrsum != cksum) {
			KFIOERR((CE_CONT,
			    "%s: checksum error "
			    "(actual 0x%x, expected 0x%x)\n",
			    filename, hdrsum, cksum));
		}
		KFIOERR((CE_CONT,
		    "%s: header information incorrect", filename));
		return (EINVAL);
	}

	ASSERT(hdr.nvpf_size >= 0);

	buf = kmem_alloc(hdr.nvpf_size, KM_SLEEP);
	n = kobj_read_file(file, buf, hdr.nvpf_size, offset);
	if (n != hdr.nvpf_size) {
		kmem_free(buf, hdr.nvpf_size);
		kobj_close_file(file);
		if (n < 0) {
			KFIOERR((CE_CONT, "%s: read error %d", filename, n));
		} else {
			KFIOERR((CE_CONT, "%s: incomplete read %d/%lld",
				filename, n, (longlong_t)hdr.nvpf_size));
		}
		return (EINVAL);
	}
	offset += n;

	rval = kobj_read_file(file, &c, 1, offset);
	kobj_close_file(file);
	if (rval > 0) {
		KFIOERR((CE_CONT, "%s is larger than %lld\n",
			filename, (longlong_t)hdr.nvpf_size));
		kmem_free(buf, hdr.nvpf_size);
		return (EINVAL);
	}

	cksum = nvp_cksum((uchar_t *)buf, hdr.nvpf_size);
	if (hdr.nvpf_chksum != cksum) {
		KFIOERR((CE_CONT,
		    "%s: checksum error (actual 0x%x, expected 0x%x)\n",
		    filename, hdr.nvpf_chksum, cksum));
		kmem_free(buf, hdr.nvpf_size);
		return (EINVAL);
	}

	nvl = NULL;
	rval = nvlist_unpack(buf, hdr.nvpf_size, &nvl, 0);
	if (rval != 0) {
		KFIOERR((CE_CONT, "%s: error %d unpacking nvlist\n",
			filename, rval));
		kmem_free(buf, hdr.nvpf_size);
		return (EINVAL);
	}

	kmem_free(buf, hdr.nvpf_size);
	*ret_nvlist = nvl;
	return (0);
}

static int
kfcreate(char *filename, kfile_t **kfilep)
{
	kfile_t	*fp;
	int	rval;

	ASSERT(modrootloaded);

	fp = kmem_alloc(sizeof (kfile_t), KM_SLEEP);

	fp->kf_vnflags = FCREAT | FWRITE | FTRUNC;
	fp->kf_fname = filename;
	fp->kf_fpos = 0;
	fp->kf_state = 0;

	KFDEBUG((CE_CONT, "create: %s flags 0x%x\n",
		filename, fp->kf_vnflags));
	rval = vn_open(filename, UIO_SYSSPACE, fp->kf_vnflags,
	    0444, &fp->kf_vp, CRCREAT, 0);
	if (rval != 0) {
		kmem_free(fp, sizeof (kfile_t));
		KFDEBUG((CE_CONT, "%s: create error %d\n",
			filename, rval));
		return (rval);
	}

	*kfilep = fp;
	return (0);
}

static int
kfremove(char *filename)
{
	int rval;

	KFDEBUG((CE_CONT, "remove: %s\n", filename));
	rval = vn_remove(filename, UIO_SYSSPACE, RMFILE);
	if (rval != 0) {
		KFDEBUG((CE_CONT, "%s: remove error %d\n",
			filename, rval));
	}
	return (rval);
}

static int
kfread(kfile_t *fp, char *buf, ssize_t bufsiz, ssize_t *ret_n)
{
	ssize_t		resid;
	int		err;
	ssize_t		n;

	ASSERT(modrootloaded);

	if (fp->kf_state != 0)
		return (fp->kf_state);

	err = vn_rdwr(UIO_READ, fp->kf_vp, buf, bufsiz, fp->kf_fpos,
		UIO_SYSSPACE, 0, (rlim64_t)0, kcred, &resid);
	if (err != 0) {
		KFDEBUG((CE_CONT, "%s: read error %d\n",
			fp->kf_fname, err));
		fp->kf_state = err;
		return (err);
	}

	ASSERT(resid >= 0 && resid <= bufsiz);
	n = bufsiz - resid;

	KFDEBUG1((CE_CONT, "%s: read %ld bytes ok %ld bufsiz, %ld resid\n",
		fp->kf_fname, n, bufsiz, resid));

	fp->kf_fpos += n;
	*ret_n = n;
	return (0);
}

static int
kfwrite(kfile_t *fp, char *buf, ssize_t bufsiz, ssize_t *ret_n)
{
	rlim64_t	rlimit;
	ssize_t		resid;
	int		err;
	ssize_t		len;
	ssize_t		n = 0;

	ASSERT(modrootloaded);

	if (fp->kf_state != 0)
		return (fp->kf_state);

	len = bufsiz;
	rlimit = bufsiz + 1;
	for (;;) {
		err = vn_rdwr(UIO_WRITE, fp->kf_vp, buf, len, fp->kf_fpos,
			UIO_SYSSPACE, FSYNC, rlimit, kcred, &resid);
		if (err) {
			KFDEBUG((CE_CONT, "%s: write error %d\n",
				fp->kf_fname, err));
			fp->kf_state = err;
			return (err);
		}

		KFDEBUG1((CE_CONT, "%s: write %ld bytes ok %ld resid\n",
			fp->kf_fname, len-resid, resid));

		ASSERT(resid >= 0 && resid <= len);

		n += (len - resid);
		if (resid == 0)
			break;

		if (resid == len) {
			KFDEBUG((CE_CONT, "%s: filesystem full?\n",
				fp->kf_fname));
			fp->kf_state = ENOSPC;
			return (ENOSPC);
		}

		len -= resid;
		buf += len;
		fp->kf_fpos += len;
		len = resid;
	}

	ASSERT(n == bufsiz);
	KFDEBUG1((CE_CONT, "%s: wrote %ld bytes ok\n", fp->kf_fname, n));

	*ret_n = n;
	return (0);
}


static int
kfclose(kfile_t *fp)
{
	int		rval;

	KFDEBUG((CE_CONT, "close: %s\n", fp->kf_fname));

	if ((fp->kf_vnflags & FWRITE) && fp->kf_state == 0) {
		rval = VOP_FSYNC(fp->kf_vp, FSYNC,  kcred);
		if (rval != 0) {
			KFIOERR((CE_CONT, "%s: sync error %d\n",
				fp->kf_fname, rval));
		}
		KFDEBUG((CE_CONT, "%s: sync ok\n", fp->kf_fname));
	}

	rval = VOP_CLOSE(fp->kf_vp, fp->kf_vnflags, 1, (offset_t)0, kcred);
	if (rval != 0) {
		if (fp->kf_state == 0) {
			KFIOERR((CE_CONT, "%s: close error %d\n",
				fp->kf_fname, rval));
		}
	} else {
		if (fp->kf_state == 0)
			KFDEBUG((CE_CONT, "%s: close ok\n", fp->kf_fname));
	}

	VN_RELE(fp->kf_vp);
	kmem_free(fp, sizeof (kfile_t));
	return (rval);
}

static int
kfrename(char *oldname, char *newname)
{
	int rval;

	ASSERT(modrootloaded);

	KFDEBUG((CE_CONT, "renaming %s to %s\n", oldname, newname));

	if ((rval = vn_rename(oldname, newname, UIO_SYSSPACE)) != 0) {
		KFDEBUG((CE_CONT, "rename %s to %s: %d\n",
			oldname, newname, rval));
	}

	return (rval);
}

static int
fwrite_nvlist(nvfd_t *nvfd, nvlist_t *nvl)
{
	char	*buf;
	char	*nvbuf;
	kfile_t	*fp;
	char	*newname;
	int	len, err;
	int	rval;
	size_t	buflen;
	ssize_t	n;

	ASSERT(modrootloaded);

	nvbuf = NULL;
	rval = nvlist_pack(nvl, &nvbuf, &buflen, NV_ENCODE_NATIVE, 0);
	if (rval != 0) {
		KFIOERR((CE_CONT, "%s: error %d packing nvlist\n",
			nvfd->nvf_name, rval));
		return (DDI_FAILURE);
	}

	buf = kmem_alloc(sizeof (nvpf_hdr_t) + buflen, KM_SLEEP);
	bzero(buf, sizeof (nvpf_hdr_t));

	((nvpf_hdr_t *)buf)->nvpf_magic = NVPF_HDR_MAGIC;
	((nvpf_hdr_t *)buf)->nvpf_version = NVPF_HDR_VERSION;
	((nvpf_hdr_t *)buf)->nvpf_size = buflen;
	((nvpf_hdr_t *)buf)->nvpf_chksum = nvp_cksum((uchar_t *)nvbuf, buflen);
	((nvpf_hdr_t *)buf)->nvpf_hdr_chksum =
		nvp_cksum((uchar_t *)buf, sizeof (nvpf_hdr_t));

	bcopy(nvbuf, buf + sizeof (nvpf_hdr_t), buflen);
	kmem_free(nvbuf, buflen);
	buflen += sizeof (nvpf_hdr_t);

	len = strlen(nvfd->nvf_name) + MAX_SUFFIX_LEN + 2;
	newname = kmem_alloc(len, KM_SLEEP);


	(void) sprintf(newname, "%s.%s",
		nvfd->nvf_name, NEW_FILENAME_SUFFIX);

	/*
	 * To make it unlikely we suffer data loss, write
	 * data to the new temporary file.  Once successful
	 * complete the transaction by renaming the new file
	 * to replace the previous.
	 */

	rval = DDI_SUCCESS;
	if ((err = kfcreate(newname, &fp)) == 0) {
		err = kfwrite(fp, buf, buflen, &n);
		if (err) {
			KFIOERR((CE_CONT, "%s: write error - %d\n",
				newname, err));
			if (err == EROFS)
				NVF_MARK_READONLY(nvfd);
			rval = DDI_FAILURE;
		} else {
			if (n != buflen) {
				KFIOERR((CE_CONT,
				    "%s: partial write %ld of %ld bytes\n",
				    newname, n, buflen));
				KFIOERR((CE_CONT,
				    "%s: filesystem may be full?\n", newname));
				rval = DDI_FAILURE;
			}
		}
		if ((err = kfclose(fp)) != 0) {
			KFIOERR((CE_CONT, "%s: close error\n", newname));
			rval = DDI_FAILURE;
		}
		if (rval != DDI_SUCCESS) {
			if (kfremove(newname) != 0) {
				KFIOERR((CE_CONT, "%s: remove failed\n",
				    newname));
			}
		}
	} else {
		KFIOERR((CE_CONT, "%s: create failed - %d\n",
			nvfd->nvf_name, err));
		if (err == EROFS)
			NVF_MARK_READONLY(nvfd);
		rval = DDI_FAILURE;
	}

	if (rval == DDI_SUCCESS) {
		if (kfrename(newname, nvfd->nvf_name) != 0) {
			KFIOERR((CE_CONT, "%s: rename from %s failed\n",
				newname, nvfd->nvf_name));
			rval = DDI_FAILURE;
		}
	}

	kmem_free(newname, len);
	kmem_free(buf, buflen);

	return (rval);
}


static void
nvp_free(nvp_list_t *np)
{
	if (np->nvp_devpath)
		kmem_free(np->nvp_devpath, strlen(np->nvp_devpath)+1);
	if (np->nvp_devid)
		kmem_free(np->nvp_devid, ddi_devid_sizeof(np->nvp_devid));

	kmem_free(np, sizeof (nvp_list_t));
}

static void
nvp_list_free(nvp_list_t *nvp)
{
	nvp_list_t	*np;
	nvp_list_t	*next;

	for (np = nvp; np; np = next) {
		next = np->nvp_next;
		nvp_free(np);
	}
}

/*
 * Free the devid-related information in an nvp element
 * If no more data is stored in the nvp element, free
 * it and unlink it from the list
 *
 * Since at present there is no further use of nvp's,
 * there's nothing to check.
 */
static nvp_list_t *
nfd_devid_free_and_unlink(nvfd_t *nvf, nvp_list_t *np)
{
	nvp_list_t *pv, *next;

	pv = np->nvp_prev;
	next = np->nvp_next;
	nvp_free(np);

	/* remove element at head */
	if (pv == NULL) {
		if (next)
			next->nvp_prev = NULL;
		nvf->nvf_list = next;
	}
	/* remove element at tail */
	if (next == NULL) {
		if (pv)
			pv->nvp_next = NULL;
		nvf->nvf_tail = pv;
	}
	/* remove element in the middle, neither head nor tail */
	if (pv && next) {
		pv->nvp_next = next;
		next->nvp_prev = pv;
	}

	return (next);
}

static void
nfd_devid_link(nvfd_t *nvf, nvp_list_t *np)
{
	if (nvf->nvf_list == NULL) {
		nvf->nvf_list = np;
	} else {
		nvf->nvf_tail->nvp_next = np;
	}
	np->nvp_next = NULL;
	np->nvp_prev = nvf->nvf_tail;
	nvf->nvf_tail = np;
}

/*
 * Convert a device path/nvlist pair to an nvp_list_t
 * Used to parse the nvlist format when reading
 */
static nvp_list_t *
nvlist_to_nvp(nvlist_t *nvl, char *name)
{
	nvp_list_t *np;
	ddi_devid_t devidp;
	int rval;
	uint_t n;

	np = kmem_zalloc(sizeof (nvp_list_t), KM_SLEEP);
	np->nvp_devpath = i_ddi_strdup(name, KM_SLEEP);

	NVP_DEVID_DEBUG_PATH((np->nvp_devpath));

	/*
	 * check path for a devid
	 */
	np->nvp_devid = NULL;
	rval = nvlist_lookup_byte_array(nvl,
		DP_DEVID_ID, (uchar_t **)&devidp, &n);
	if (rval == 0) {
		if (ddi_devid_valid(devidp) == DDI_SUCCESS) {
			ASSERT(n == ddi_devid_sizeof(devidp));
			np->nvp_devid = kmem_alloc(n, KM_SLEEP);
			(void) bcopy(devidp, np->nvp_devid, n);
			NVP_DEVID_DEBUG_DEVID((np->nvp_devid));
		} else {
			DEVIDERR((CE_CONT,
			    "%s: invalid devid\n", np->nvp_devpath));
		}
	}

	return (np);
}

/*
 * Convert a list of nvp_list_t's to a single nvlist
 * Used when writing the nvlist file
 */
static int
nvp_to_nvlist(nvfd_t *nvfd, nvlist_t **ret_nvl)
{
	nvlist_t	*nvl, *sub_nvl;
	nvp_list_t	*np;
	int		rval;

	ASSERT(modrootloaded);

	rval = nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);
	if (rval != 0) {
		KFIOERR((CE_CONT, "%s: nvlist alloc error %d\n",
			nvfd->nvf_name, rval));
		return (DDI_FAILURE);
	}

	for (np = nvfd->nvf_list; np; np = np->nvp_next) {
		if (np->nvp_devid == NULL)
		    continue;
		NVP_DEVID_DEBUG_PATH(np->nvp_devpath);
		rval = nvlist_alloc(&sub_nvl, NV_UNIQUE_NAME, KM_SLEEP);
		if (rval != 0) {
			KFIOERR((CE_CONT, "%s: nvlist alloc error %d\n",
				nvfd->nvf_name, rval));
			sub_nvl = NULL;
			goto err;
		}

		if (np->nvp_devid) {
			rval = nvlist_add_byte_array(sub_nvl, DP_DEVID_ID,
				(uchar_t *)np->nvp_devid,
				ddi_devid_sizeof(np->nvp_devid));
			if (rval == 0) {
				NVP_DEVID_DEBUG_DEVID(np->nvp_devid);
			} else {
				KFIOERR((CE_CONT,
				    "%s: nvlist add error %d (devid)\n",
				    nvfd->nvf_name, rval));
				goto err;
			}
		}

		rval = nvlist_add_nvlist(nvl, np->nvp_devpath, sub_nvl);
		if (rval != 0) {
			KFIOERR((CE_CONT, "%s: nvlist add error %d (sublist)\n",
			    nvfd->nvf_name, rval));
			goto err;
		}
		nvlist_free(sub_nvl);
	}

	*ret_nvl = nvl;
	return (DDI_SUCCESS);

err:
	if (sub_nvl)
		nvlist_free(sub_nvl);
	nvlist_free(nvl);
	*ret_nvl = NULL;
	return (DDI_FAILURE);
}


/*
 * Read a file in the nvlist format
 *	EIO - i/o error during read
 *	ENOENT - file not found
 *	EINVAL - file contents corrupted
 */
static int
fread_nvp_list(nvfd_t *nvfd)
{
	nvlist_t	*nvl;
	nvpair_t	*nvp;
	char		*name;
	nvlist_t	*sublist;
	int		rval;
	nvp_list_t	*np;
	nvp_list_t	*nvp_list = NULL;
	nvp_list_t	*nvp_tail = NULL;

	nvfd->nvf_list = NULL;
	nvfd->nvf_tail = NULL;

	rval = fread_nvlist(nvfd->nvf_name, &nvl);
	if (rval != 0)
		return (rval);
	ASSERT(nvl != NULL);

	nvp = NULL;
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		name = nvpair_name(nvp);
		ASSERT(strlen(name) > 0);

		switch (nvpair_type(nvp)) {
		case DATA_TYPE_NVLIST:
			rval = nvpair_value_nvlist(nvp, &sublist);
			if (rval != 0) {
				KFIOERR((CE_CONT,
				    "nvpair_value_nvlist error %s %d\n",
				    name, rval));
				goto error;
			}

			/*
			 * convert nvlist for this device to
			 * an nvp_list_t struct
			 */
			np = nvlist_to_nvp(sublist, name);
			np->nvp_next = NULL;
			np->nvp_prev = nvp_tail;

			if (nvp_list == NULL) {
				nvp_list = np;
			} else {
				nvp_tail->nvp_next = np;
			}
			nvp_tail = np;

			break;

		default:
			KFIOERR((CE_CONT, "%s: %s unsupported data type %d\n",
				nvfd->nvf_name, name, nvpair_type(nvp)));
			rval = EINVAL;
			goto error;
		}
	}

	nvlist_free(nvl);

	nvfd->nvf_list = nvp_list;
	nvfd->nvf_tail = nvp_tail;

	return (0);

error:
	nvlist_free(nvl);
	if (nvp_list)
		nvp_list_free(nvp_list);
	return (rval);
}


static int
i_ddi_read_one_nvfile(nvfd_t *nvfd)
{
	int rval;

	KFDEBUG((CE_CONT, "Reading %s\n", nvfd->nvf_name));

	rval = fread_nvp_list(nvfd);
	if (rval) {
		switch (rval) {
		case EIO:
			nvfd->nvf_flags |= NVF_REBUILD_MSG;
			cmn_err(CE_WARN, "%s: I/O error",
				nvfd->nvf_name);
			break;
		case ENOENT:
			nvfd->nvf_flags |= NVF_CREATE_MSG;
			KFIOERR((CE_CONT, "%s: not found\n",
				nvfd->nvf_name));
			break;
		case EINVAL:
		default:
			nvfd->nvf_flags |= NVF_REBUILD_MSG;
			cmn_err(CE_WARN, "%s: data file corrupted",
				nvfd->nvf_name);
			break;
		}
	}
	return (rval);
}

void
i_ddi_read_devices_files(void)
{
	nvfd_t nvfd;
	int rval;

	if (devid_cache_read_disable)
		return;

	nvfd.nvf_name = dcfd->nvf_name;
	nvfd.nvf_flags = 0;
	nvfd.nvf_list = NULL;
	nvfd.nvf_tail = NULL;
	rw_init(&nvfd.nvf_lock, NULL, RW_DRIVER, NULL);

	rval = i_ddi_read_one_nvfile(&nvfd);

	rw_enter(&dcfd->nvf_lock, RW_WRITER);

	if (rval == 0) {
		if (dcfd->nvf_list != NULL) {
			nvp_list_free(dcfd->nvf_list);
		}
		dcfd->nvf_list = nvfd.nvf_list;
		dcfd->nvf_tail = nvfd.nvf_tail;
	}
	dcfd->nvf_flags = nvfd.nvf_flags;

	rw_exit(&dcfd->nvf_lock);

	rw_destroy(&nvfd.nvf_lock);
}

static int
e_devid_do_discovery(void)
{
	ASSERT(mutex_owned(&devid_discovery_mutex));

	if (i_ddi_io_initialized() == 0) {
		if (devid_discovery_boot > 0) {
			devid_discovery_boot--;
			return (1);
		}
	} else {
		if (devid_discovery_postboot_always > 0)
			return (1);
		if (devid_discovery_postboot > 0) {
			devid_discovery_postboot--;
			return (1);
		}
		if (devid_discovery_secs > 0) {
			if ((ddi_get_lbolt() - devid_last_discovery) >
			    drv_usectohz(devid_discovery_secs * MICROSEC)) {
				return (1);
			}
		}
	}

	DEVID_LOG_DISC((CE_CONT, "devid_discovery: no discovery\n"));
	return (0);
}

static void
e_ddi_devid_hold_by_major(major_t major)
{
	DEVID_LOG_DISC((CE_CONT,
	    "devid_discovery: ddi_hold_installed_driver %d\n", major));

	if (ddi_hold_installed_driver(major) == NULL)
		return;

	ddi_rele_driver(major);
}

static char *e_ddi_devid_hold_driver_list[] = { "sd", "ssd", "dad" };

#define	N_DRIVERS_TO_HOLD	\
	(sizeof (e_ddi_devid_hold_driver_list) / sizeof (char *))


static void
e_ddi_devid_hold_installed_driver(ddi_devid_t devid)
{
	impl_devid_t	*id = (impl_devid_t *)devid;
	major_t		major, hint_major;
	char		hint[DEVID_HINT_SIZE + 1];
	char		**drvp;
	int		i;

	/* Count non-null bytes */
	for (i = 0; i < DEVID_HINT_SIZE; i++)
		if (id->did_driver[i] == '\0')
			break;

	/* Make a copy of the driver hint */
	bcopy(id->did_driver, hint, i);
	hint[i] = '\0';

	/* search for the devid using the hint driver */
	hint_major = ddi_name_to_major(hint);
	if (hint_major != (major_t)-1) {
		e_ddi_devid_hold_by_major(hint_major);
	}

	drvp = e_ddi_devid_hold_driver_list;
	for (i = 0; i < N_DRIVERS_TO_HOLD; i++, drvp++) {
		major = ddi_name_to_major(*drvp);
		if (major != (major_t)-1 && major != hint_major) {
			e_ddi_devid_hold_by_major(major);
		}
	}
}


/*
 * Return success if discovery was attempted, to indicate
 * that the desired device may now be available.
 */
int
e_ddi_devid_discovery(ddi_devid_t devid)
{
	int flags;
	int rval = DDI_SUCCESS;

	mutex_enter(&devid_discovery_mutex);

	if (devid_discovery_busy) {
		DEVID_LOG_DISC((CE_CONT, "devid_discovery: busy\n"));
		while (devid_discovery_busy) {
			cv_wait(&devid_discovery_cv, &devid_discovery_mutex);
		}
	} else if (e_devid_do_discovery()) {
		devid_discovery_busy = 1;
		mutex_exit(&devid_discovery_mutex);

		if (i_ddi_io_initialized() == 0) {
			e_ddi_devid_hold_installed_driver(devid);
		} else {
			DEVID_LOG_DISC((CE_CONT,
			    "devid_discovery: ndi_devi_config\n"));
			flags = NDI_DEVI_PERSIST | NDI_CONFIG | NDI_NO_EVENT;
			if (i_ddi_io_initialized())
				flags |= NDI_DRV_CONF_REPROBE;
			(void) ndi_devi_config(ddi_root_node(), flags);
		}

		mutex_enter(&devid_discovery_mutex);
		devid_discovery_busy = 0;
		cv_broadcast(&devid_discovery_cv);
		if (devid_discovery_secs > 0)
			devid_last_discovery = ddi_get_lbolt();
		DEVID_LOG_DISC((CE_CONT, "devid_discovery: done\n"));
	} else {
		rval = DDI_FAILURE;
		DEVID_LOG_DISC((CE_CONT, "no devid discovery\n"));
	}

	mutex_exit(&devid_discovery_mutex);

	return (rval);
}

int
e_devid_cache_register(dev_info_t *dip, ddi_devid_t devid)
{
	nvp_list_t *np;
	nvp_list_t *new_nvp;
	ddi_devid_t new_devid;
	int new_devid_size;
	char *path, *fullpath;
	ddi_devid_t free_devid = NULL;
	int pathlen;

	ASSERT(ddi_devid_valid(devid) == DDI_SUCCESS);

	fullpath = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, fullpath);
	pathlen = strlen(fullpath) + 1;
	path = kmem_alloc(pathlen, KM_SLEEP);
	bcopy(fullpath, path, pathlen);
	kmem_free(fullpath, MAXPATHLEN);

	DEVID_LOG_REG(("register", devid, path));

	new_nvp = kmem_zalloc(sizeof (nvp_list_t), KM_SLEEP);
	new_devid_size = ddi_devid_sizeof(devid);
	new_devid = kmem_alloc(new_devid_size, KM_SLEEP);
	(void) bcopy(devid, new_devid, new_devid_size);

	rw_enter(&dcfd->nvf_lock, RW_WRITER);

	for (np = dcfd->nvf_list; np != NULL; np = np->nvp_next) {
		if (strcmp(path, np->nvp_devpath) == 0) {
			DEVID_DEBUG2((CE_CONT,
			    "register: %s path match\n", path));
			if (np->nvp_devid == NULL) {
			    replace:
				np->nvp_devid = new_devid;
				np->nvp_flags |=
					NVP_DEVID_DIP | NVP_DEVID_REGISTERED;
				np->nvp_dip = dip;
				NVF_MARK_DIRTY(dcfd);
				rw_exit(&dcfd->nvf_lock);
				kmem_free(new_nvp, sizeof (nvp_list_t));
				kmem_free(path, pathlen);
				goto exit;
			}
			if (ddi_devid_valid(np->nvp_devid) != DDI_SUCCESS) {
				/* replace invalid devid */
				free_devid = np->nvp_devid;
				goto replace;
			}
			/*
			 * We're registering an already-cached path
			 * Does the device's devid match the cache?
			 */
			if (ddi_devid_compare(devid, np->nvp_devid) != 0) {
				DEVID_DEBUG((CE_CONT, "devid register: "
				    "devid %s does not match\n", path));
				/*
				 * Replace cached devid for this path
				 * with newly registered devid.  A devid
				 * may map to multiple paths but one path
				 * should only map to one devid.
				 */
				(void) nfd_devid_free_and_unlink(
					dcfd, np);
				np = NULL;
				break;
			} else {
				DEVID_DEBUG2((CE_CONT,
				    "devid register: %s devid match\n", path));
				np->nvp_flags |=
					NVP_DEVID_DIP | NVP_DEVID_REGISTERED;
				np->nvp_dip = dip;
				rw_exit(&dcfd->nvf_lock);
				kmem_free(new_nvp, sizeof (nvp_list_t));
				kmem_free(path, pathlen);
				kmem_free(new_devid, new_devid_size);
				return (DDI_SUCCESS);
			}
		}
	}

	/*
	 * Add newly registered devid to the cache
	 */
	ASSERT(np == NULL);

	new_nvp->nvp_devpath = path;
	new_nvp->nvp_flags = NVP_DEVID_DIP | NVP_DEVID_REGISTERED;
	new_nvp->nvp_dip = dip;
	new_nvp->nvp_devid = new_devid;

	NVF_MARK_DIRTY(dcfd);
	nfd_devid_link(dcfd, new_nvp);

	rw_exit(&dcfd->nvf_lock);

exit:
	if (free_devid)
		kmem_free(free_devid, ddi_devid_sizeof(free_devid));

	wake_nvpflush_daemon(dcfd);

	return (DDI_SUCCESS);
}

/*
 * Unregister a device's devid
 * Called as an instance detachs
 * Invalidate the devid's devinfo reference
 * Devid-path remains in the cache
 */
void
e_devid_cache_unregister(dev_info_t *dip)
{
	nvp_list_t *np;

	rw_enter(&dcfd->nvf_lock, RW_WRITER);

	for (np = dcfd->nvf_list; np != NULL; np = np->nvp_next) {
		if (np->nvp_devid == NULL)
			continue;
		if ((np->nvp_flags & NVP_DEVID_DIP) && np->nvp_dip == dip) {
			DEVID_LOG_UNREG((CE_CONT,
				"unregister: %s\n", np->nvp_devpath));
			np->nvp_flags &= ~NVP_DEVID_DIP;
			np->nvp_dip = NULL;
			break;
		}
	}

	rw_exit(&dcfd->nvf_lock);
}


void
e_devid_cache_cleanup(void)
{
	nvp_list_t *np, *next;

	rw_enter(&dcfd->nvf_lock, RW_WRITER);

	for (np = dcfd->nvf_list; np != NULL; np = next) {
		next = np->nvp_next;
		if (np->nvp_devid == NULL)
			continue;
		if ((np->nvp_flags & NVP_DEVID_REGISTERED) == 0) {
			DEVID_LOG_REMOVE((CE_CONT,
				    "cleanup: %s\n", np->nvp_devpath));
			NVF_MARK_DIRTY(dcfd);
			next = nfd_devid_free_and_unlink(dcfd, np);
		}
	}

	rw_exit(&dcfd->nvf_lock);

	if (NVF_IS_DIRTY(dcfd))
		wake_nvpflush_daemon(dcfd);
}


/*
 * Build a list of dev_t's for a device/devid
 *
 * The effect of this function is cumulative, adding dev_t's
 * for the device to the list of all dev_t's for a given
 * devid.
 */
static void
e_devid_minor_to_devlist(
	dev_info_t	*dip,
	char		*minor_name,
	int		ndevts_alloced,
	int		*devtcntp,
	dev_t		*devtsp)
{
	struct ddi_minor_data	*dmdp;
	int			minor_all = 0;
	int			ndevts = *devtcntp;

	ASSERT(i_ddi_node_state(dip) >= DS_ATTACHED);

	/* are we looking for a set of minor nodes? */
	if ((minor_name == DEVID_MINOR_NAME_ALL) ||
	    (minor_name == DEVID_MINOR_NAME_ALL_CHR) ||
	    (minor_name == DEVID_MINOR_NAME_ALL_BLK))
		minor_all = 1;

	mutex_enter(&(DEVI(dip)->devi_lock));

	/* Find matching minor names */
	for (dmdp = DEVI(dip)->devi_minor; dmdp; dmdp = dmdp->next) {

		/* Skip non-minors, and non matching minor names */
		if ((dmdp->type != DDM_MINOR) || ((minor_all == 0) &&
		    strcmp(dmdp->ddm_name, minor_name)))
			continue;

		/* filter out minor_all mismatches */
		if (minor_all &&
		    (((minor_name == DEVID_MINOR_NAME_ALL_CHR) &&
		    (dmdp->ddm_spec_type != S_IFCHR)) ||
		    ((minor_name == DEVID_MINOR_NAME_ALL_BLK) &&
		    (dmdp->ddm_spec_type != S_IFBLK))))
			continue;

		if (ndevts < ndevts_alloced)
			devtsp[ndevts] = dmdp->ddm_dev;
		ndevts++;
	}

	mutex_exit(&(DEVI(dip)->devi_lock));

	*devtcntp = ndevts;
}

/*
 * Search for cached entries matching a devid
 * Return two lists:
 *	a list of dev_info nodes, for those devices in the attached state
 *	a list of pathnames whose instances registered the given devid
 * If the lists passed in are not sufficient to return the matching
 * references, return the size of lists required.
 * The dev_info nodes are returned with a hold that the caller must release.
 */
static int
e_devid_cache_devi_path_lists(ddi_devid_t devid, int retmax,
	int *retndevis, dev_info_t **retdevis, int *retnpaths, char **retpaths)
{
	nvp_list_t *np;
	int ndevis, npaths;
	dev_info_t *dip, *pdip;
	int circ;
	int maxdevis = 0;
	int maxpaths = 0;

	ndevis = 0;
	npaths = 0;
	for (np = dcfd->nvf_list; np != NULL; np = np->nvp_next) {
		if (np->nvp_devid == NULL)
			continue;
		if (ddi_devid_valid(np->nvp_devid) != DDI_SUCCESS) {
			DEVIDERR((CE_CONT,
			    "find: invalid devid %s\n",
			    np->nvp_devpath));
			continue;
		}
		if (ddi_devid_compare(devid, np->nvp_devid) == 0) {
			DEVID_DEBUG2((CE_CONT,
			    "find: devid match: %s 0x%x\n",
			    np->nvp_devpath, np->nvp_flags));
			DEVID_LOG_MATCH(("find", devid, np->nvp_devpath));
			DEVID_LOG_PATHS((CE_CONT, "%s\n", np->nvp_devpath));

			/*
			 * Check if we have a cached devinfo reference for this
			 * devid.  Place a hold on it to prevent detach
			 * Otherwise, use the path instead.
			 * Note: returns with a hold on each dev_info
			 * node in the list.
			 */
			dip = NULL;
			if (np->nvp_flags & NVP_DEVID_DIP) {
				pdip = ddi_get_parent(np->nvp_dip);
				if (ndi_devi_tryenter(pdip, &circ)) {
					dip = np->nvp_dip;
					ndi_hold_devi(dip);
					ndi_devi_exit(pdip, circ);
					ASSERT(!DEVI_IS_ATTACHING(dip));
					ASSERT(!DEVI_IS_DETACHING(dip));
				} else {
					DEVID_LOG_DETACH((CE_CONT,
					    "may be detaching: %s\n",
					    np->nvp_devpath));
				}
			}

			if (dip) {
				if (ndevis < retmax) {
					retdevis[ndevis++] = dip;
				} else {
					ndi_rele_devi(dip);
				}
				maxdevis++;
			} else {
				if (npaths < retmax)
					retpaths[npaths++] = np->nvp_devpath;
				maxpaths++;
			}
		}
	}

	*retndevis = ndevis;
	*retnpaths = npaths;
	return (maxdevis > maxpaths ? maxdevis : maxpaths);
}


/*
 * Search the devid cache, returning dev_t list for all
 * device paths mapping to the device identified by the
 * given devid.
 *
 * Primary interface used by ddi_lyr_devid_to_devlist()
 */
int
e_devid_cache_to_devt_list(ddi_devid_t devid, char *minor_name,
	int *retndevts, dev_t **retdevts)
{
	char		*path, **paths;
	int		i, j, n;
	dev_t		*devts, *udevts;
	int		ndevts, undevts, ndevts_alloced;
	dev_info_t	*devi, **devis;
	int		ndevis, npaths, nalloced;
	ddi_devid_t	match_devid;

	DEVID_LOG_FIND(("find", devid, NULL));

	ASSERT(ddi_devid_valid(devid) == DDI_SUCCESS);
	if (ddi_devid_valid(devid) != DDI_SUCCESS) {
		DEVID_LOG_ERR(("invalid devid", devid, NULL));
		return (DDI_FAILURE);
	}

	nalloced = 128;

	for (;;) {
		paths = kmem_zalloc(nalloced * sizeof (char *), KM_SLEEP);
		devis = kmem_zalloc(nalloced * sizeof (dev_info_t *), KM_SLEEP);

		rw_enter(&dcfd->nvf_lock, RW_READER);
		n = e_devid_cache_devi_path_lists(devid, nalloced,
			&ndevis, devis, &npaths, paths);
		if (n <= nalloced)
			break;
		rw_exit(&dcfd->nvf_lock);
		for (i = 0; i < ndevis; i++)
			ndi_rele_devi(devis[i]);
		kmem_free(paths, nalloced * sizeof (char *));
		kmem_free(devis, nalloced * sizeof (dev_info_t *));
		nalloced = n + 128;
	}

	for (i = 0; i < npaths; i++) {
		path = i_ddi_strdup(paths[i], KM_SLEEP);
		paths[i] = path;
	}
	rw_exit(&dcfd->nvf_lock);

	if (ndevis == 0 && npaths == 0) {
		DEVID_LOG_ERR(("no devid found", devid, NULL));
		kmem_free(paths, nalloced * sizeof (char *));
		kmem_free(devis, nalloced * sizeof (dev_info_t *));
		return (DDI_FAILURE);
	}

	ndevts_alloced = 128;
restart:
	ndevts = 0;
	devts = kmem_alloc(ndevts_alloced * sizeof (dev_t), KM_SLEEP);
	for (i = 0; i < ndevis; i++) {
		ASSERT(!DEVI_IS_ATTACHING(devis[i]));
		ASSERT(!DEVI_IS_DETACHING(devis[i]));
		e_devid_minor_to_devlist(devis[i], minor_name,
			ndevts_alloced, &ndevts, devts);
		if (ndevts > ndevts_alloced) {
			kmem_free(devts, ndevts_alloced * sizeof (dev_t));
			ndevts_alloced += 128;
			goto restart;
		}
	}
	for (i = 0; i < npaths; i++) {
		DEVID_LOG_LOOKUP((CE_CONT, "lookup %s\n", paths[i]));
		devi = e_ddi_hold_devi_by_path(paths[i], 0);
		if (devi == NULL) {
			DEVID_LOG_STALE(("stale device reference",
			    devid, paths[i]));
			continue;
		}
		/*
		 * Verify the newly attached device registered a matching devid
		 */
		if (i_ddi_devi_get_devid(DDI_DEV_T_ANY, devi,
		    &match_devid) != DDI_SUCCESS) {
			DEVIDERR((CE_CONT,
			    "%s: no devid registered on attach\n",
			    paths[i]));
			ddi_release_devi(devi);
			continue;
		}

		if (ddi_devid_compare(devid, match_devid) != 0) {
			DEVID_LOG_STALE(("new devid registered",
			    devid, paths[i]));
			ddi_release_devi(devi);
			ddi_devid_free(match_devid);
			continue;
		}
		ddi_devid_free(match_devid);

		e_devid_minor_to_devlist(devi, minor_name,
			ndevts_alloced, &ndevts, devts);
		ddi_release_devi(devi);
		if (ndevts > ndevts_alloced) {
			kmem_free(devts,
			    ndevts_alloced * sizeof (dev_t));
			ndevts_alloced += 128;
			goto restart;
		}
	}

	/* drop hold from e_devid_cache_devi_path_lists */
	for (i = 0; i < ndevis; i++) {
		ndi_rele_devi(devis[i]);
	}
	for (i = 0; i < npaths; i++) {
		kmem_free(paths[i], strlen(paths[i]) + 1);
	}
	kmem_free(paths, nalloced * sizeof (char *));
	kmem_free(devis, nalloced * sizeof (dev_info_t *));

	if (ndevts == 0) {
		DEVID_LOG_ERR(("no devid found", devid, NULL));
		kmem_free(devts, ndevts_alloced * sizeof (dev_t));
		return (DDI_FAILURE);
	}

	/*
	 * Build the final list of sorted dev_t's with duplicates collapsed so
	 * returned results are consistent. This prevents implementation
	 * artifacts from causing unnecessary changes in SVM namespace.
	 */
	/* bubble sort */
	for (i = 0; i < (ndevts - 1); i++) {
		for (j = 0; j < ((ndevts - 1) - i); j++) {
			if (devts[j + 1] < devts[j]) {
				n = devts[j];
				devts[j] = devts[j + 1];
				devts[j + 1] = n;
			}
		}
	}

	/* determine number of unique values */
	for (undevts = ndevts, i = 1; i < ndevts; i++) {
		if (devts[i - 1] == devts[i])
			undevts--;
	}

	/* allocate unique */
	udevts = kmem_alloc(undevts * sizeof (dev_t), KM_SLEEP);

	/* copy unique */
	udevts[0] = devts[0];
	for (i = 1, j = 1; i < ndevts; i++) {
		if (devts[i - 1] != devts[i])
			udevts[j++] = devts[i];
	}
	ASSERT(j == undevts);

	kmem_free(devts, ndevts_alloced * sizeof (dev_t));

	*retndevts = undevts;
	*retdevts = udevts;

	return (DDI_SUCCESS);
}

void
e_devid_cache_free_devt_list(int ndevts, dev_t *devt_list)
{
	kmem_free(devt_list, ndevts * sizeof (dev_t *));
}


#include <sys/callb.h>

/*
 * Allow some delay from an update of the data before flushing
 * to permit simultaneous updates of multiple changes.
 * Changes in the data are expected to be bursty, ie
 * reconfig boot or hot-plug of a new adapter.
 *
 * nvpflush_delay is in units of seconds.
 * The data should be "quiet" for this interval before
 * the repository update is triggered.
 *
 * nvpdaemon_idle_time is the number of seconds the
 * daemon will sleep idle before exiting.
 */
#define	NVPFLUSH_DELAY		10
#define	NVPDAEMON_IDLE_TIME	60

#define	TICKS_PER_SECOND	(drv_usectohz(1000000))

static int nvpflush_delay	= NVPFLUSH_DELAY;
static int nvpdaemon_idle_time	= NVPDAEMON_IDLE_TIME;

static timeout_id_t	nvpflush_id = 0;
static int		nvpflush_timer_busy = 0;
static int		nvpflush_daemon_active = 0;
static kthread_t	*nvpflush_thr_id = 0;

static int		do_nvpflush = 0;
static int		nvpbusy = 0;
static kmutex_t		nvpflush_lock;
static kcondvar_t	nvpflush_cv;
static kthread_id_t	nvpflush_thread;
static clock_t		nvpticks;

static void nvpflush_daemon(void);


void
i_ddi_start_flush_daemon(void)
{
	ASSERT(i_ddi_io_initialized());

	mutex_init(&nvpflush_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&nvpflush_cv, NULL, CV_DRIVER, NULL);

	if (NVF_IS_DIRTY(dcfd)) {
		wake_nvpflush_daemon(dcfd);
	}
}

/*ARGSUSED*/
static void
nvpflush_timeout(void *arg)
{
	clock_t nticks;

	mutex_enter(&nvpflush_lock);
	nticks = nvpticks - ddi_get_lbolt();
	if (nticks > 4) {
		nvpflush_timer_busy = 1;
		mutex_exit(&nvpflush_lock);
		nvpflush_id = timeout(nvpflush_timeout, NULL, nticks);
	} else {
		do_nvpflush = 1;
		cv_signal(&nvpflush_cv);
		nvpflush_id = 0;
		nvpflush_timer_busy = 0;
		mutex_exit(&nvpflush_lock);
	}
}

static void
wake_nvpflush_daemon(nvfd_t *nvfp)
{
	clock_t nticks;

	/*
	 * If root is readonly or the system isn't up yet
	 * don't even think about starting a flush.
	 */
	if (devid_cache_write_disable ||
	    !i_ddi_io_initialized() || NVF_IS_READONLY(nvfp))
		return;

	mutex_enter(&nvpflush_lock);

	if (nvpflush_daemon_active == 0) {
		nvpflush_daemon_active = 1;
		mutex_exit(&nvpflush_lock);
		NVPDAEMON_DEBUG((CE_CONT, "starting nvpdaemon thread\n"));
		nvpflush_thr_id = thread_create(NULL, 0,
		    (void (*)())nvpflush_daemon,
		    NULL, 0, &p0, TS_RUN, minclsyspri);
		mutex_enter(&nvpflush_lock);
	}

	nticks = nvpflush_delay * TICKS_PER_SECOND;
	nvpticks = ddi_get_lbolt() + nticks;
	if (nvpflush_timer_busy == 0) {
		nvpflush_timer_busy = 1;
		mutex_exit(&nvpflush_lock);
		nvpflush_id = timeout(nvpflush_timeout, NULL, nticks + 4);
	} else
		mutex_exit(&nvpflush_lock);
}

static int
nvpflush_one(nvfd_t *nvfd)
{
	int rval = DDI_SUCCESS;
	nvlist_t *nvl;

	rw_enter(&nvfd->nvf_lock, RW_READER);

	if (!NVF_IS_DIRTY(nvfd) || NVF_IS_READONLY(nvfd)) {
		rw_exit(&nvfd->nvf_lock);
		return (DDI_SUCCESS);
	}

	if (rw_tryupgrade(&nvfd->nvf_lock) == 0) {
		KFIOERR((CE_CONT, "nvpflush: "
		    "%s rw upgrade failed\n", nvfd->nvf_name));
		rw_exit(&nvfd->nvf_lock);
		return (DDI_FAILURE);
	}
	if (nvp_to_nvlist(nvfd, &nvl) != DDI_SUCCESS) {
		KFIOERR((CE_CONT, "nvpflush: "
		    "%s nvlist construction failed\n", nvfd->nvf_name));
		rw_exit(&nvfd->nvf_lock);
		return (DDI_FAILURE);
	}

	NVF_CLEAR_DIRTY(nvfd);
	nvfd->nvf_flags |= NVF_FLUSHING;
	rw_exit(&nvfd->nvf_lock);

	rval = fwrite_nvlist(nvfd, nvl);
	nvlist_free(nvl);

	rw_enter(&nvfd->nvf_lock, RW_WRITER);
	nvfd->nvf_flags &= ~NVF_FLUSHING;
	if (rval == DDI_FAILURE) {
		if (NVF_IS_READONLY(nvfd)) {
			rval = DDI_SUCCESS;
			nvfd->nvf_flags &= ~(NVF_ERROR | NVF_DIRTY);
		} else if ((nvfd->nvf_flags & NVF_ERROR) == 0) {
			cmn_err(CE_CONT,
			    "%s: updated failed\n", nvfd->nvf_name);
			nvfd->nvf_flags |= NVF_ERROR | NVF_DIRTY;
		}
	} else {
		if (nvfd->nvf_flags & NVF_CREATE_MSG) {
			cmn_err(CE_CONT, "!Creating %s\n", nvfd->nvf_name);
			nvfd->nvf_flags &= ~NVF_CREATE_MSG;
		}
		if (nvfd->nvf_flags & NVF_REBUILD_MSG) {
			cmn_err(CE_CONT, "!Rebuilding %s\n", nvfd->nvf_name);
			nvfd->nvf_flags &= ~NVF_REBUILD_MSG;
		}
		if (nvfd->nvf_flags & NVF_ERROR) {
			cmn_err(CE_CONT,
			    "%s: update now ok\n", nvfd->nvf_name);
			nvfd->nvf_flags &= ~NVF_ERROR;
		}
		/*
		 * The file may need to be flushed again if the cached
		 * data was touched while writing the earlier contents.
		 */
		if (NVF_IS_DIRTY(nvfd))
			rval = DDI_FAILURE;
	}

	rw_exit(&nvfd->nvf_lock);
	return (rval);
}

static void
nvpflush_daemon(void)
{
	callb_cpr_t cprinfo;
	clock_t clk;
	int rval;

	ASSERT(modrootloaded);

	nvpflush_thread = curthread;
	NVPDAEMON_DEBUG((CE_CONT, "nvpdaemon: init\n"));

	CALLB_CPR_INIT(&cprinfo, &nvpflush_lock, callb_generic_cpr, "nvp");
	mutex_enter(&nvpflush_lock);
	for (;;) {

		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		while (do_nvpflush == 0) {
			clk = cv_timedwait(&nvpflush_cv, &nvpflush_lock,
			    ddi_get_lbolt() +
				(nvpdaemon_idle_time * TICKS_PER_SECOND));
			if (clk == -1 &&
			    do_nvpflush == 0 && nvpflush_timer_busy == 0) {
				/*
				 * Note that CALLB_CPR_EXIT calls mutex_exit()
				 * on the lock passed in to CALLB_CPR_INIT,
				 * so the lock must be held when invoking it.
				 */
				CALLB_CPR_SAFE_END(&cprinfo, &nvpflush_lock);
				NVPDAEMON_DEBUG((CE_CONT, "nvpdaemon: exit\n"));
				ASSERT(mutex_owned(&nvpflush_lock));
				nvpflush_thr_id = NULL;
				nvpflush_daemon_active = 0;
				CALLB_CPR_EXIT(&cprinfo);
				thread_exit();
			}
		}
		CALLB_CPR_SAFE_END(&cprinfo, &nvpflush_lock);

		nvpbusy = 1;
		do_nvpflush = 0;
		mutex_exit(&nvpflush_lock);

		/*
		 * Try flushing what's dirty, reschedule if there's
		 * a failure or data gets marked as dirty again.
		 */
		NVPDAEMON_DEBUG((CE_CONT, "nvpdaemon: flush\n"));
		rval = nvpflush_one(dcfd);

		rw_enter(&dcfd->nvf_lock, RW_READER);
		if (rval != DDI_SUCCESS || NVF_IS_DIRTY(dcfd)) {
			rw_exit(&dcfd->nvf_lock);
			NVPDAEMON_DEBUG((CE_CONT, "nvpdaemon: dirty again\n"));
			wake_nvpflush_daemon(dcfd);
		} else
			rw_exit(&dcfd->nvf_lock);
		mutex_enter(&nvpflush_lock);
		nvpbusy = 0;
	}
}

#ifdef	DEBUG
static void
devid_log(char *fmt, ddi_devid_t devid, char *path)
{
	char *devidstr = ddi_devid_str_encode(devid, NULL);
	if (path) {
		cmn_err(CE_CONT, "%s: %s %s\n", fmt, path, devidstr);
	} else {
		cmn_err(CE_CONT, "%s: %s\n", fmt, devidstr);
	}
	ddi_devid_str_free(devidstr);
}
#endif	/* DEBUG */
