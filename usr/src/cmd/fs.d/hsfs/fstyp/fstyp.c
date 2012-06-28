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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * libfstyp module for hsfs
 */
#include <unistd.h>
#include <stropts.h>
#include <fcntl.h>
#include <stdio.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/cdio.h>
#include <sys/dkio.h>
#include <libnvpair.h>
#include <libfstyp_module.h>

#include <sys/fs/hsfs_spec.h>
#include <sys/fs/hsfs_isospec.h>

typedef struct fstyp_hsfs {
	int		fd;
	nvlist_t	*attr;
	char		hs_buf[ISO_SECTOR_SIZE];
	int		hs_pvd_sec_no;
	char		iso_buf[ISO_SECTOR_SIZE];
	int		iso_pvd_sec_no;
	char		unix_buf[ISO_SECTOR_SIZE];
	int		unix_pvd_sec_no;
	int		cdroff;
	int		cd_type;
} fstyp_hsfs_t;

#define	GETCDSECTOR(h, buf, secno, nosec) (getdisk(h, buf, \
	((secno)+(h)->cdroff)*ISO_SECTOR_SIZE, \
	(nosec)*ISO_SECTOR_SIZE))

#define	NELEM(a)	sizeof (a) / sizeof (*(a))

static int	ckvoldesc(fstyp_hsfs_t *h, int *cd_type);
static int	findhsvol(fstyp_hsfs_t *h, char *volp);
static int	findisovol(fstyp_hsfs_t *h, char *volp);
static int	findunixvol(fstyp_hsfs_t *h, char *volp);
static char	*get_old_name(char *new);
static int	rdev_is_a_cd(int rdevfd);
static int	getdisk(fstyp_hsfs_t *h, char *buf, int daddr, int size);
static void	copy_string(char *d, char *s, int maxlen);
static int	is_hsfs(fstyp_hsfs_t *h);
static int	get_attr(fstyp_hsfs_t *h);

int	fstyp_mod_init(int fd, off_t offset, fstyp_mod_handle_t *handle);
void	fstyp_mod_fini(fstyp_mod_handle_t handle);
int	fstyp_mod_ident(fstyp_mod_handle_t handle);
int	fstyp_mod_get_attr(fstyp_mod_handle_t handle, nvlist_t **attrp);
int	fstyp_mod_dump(fstyp_mod_handle_t handle, FILE *fout, FILE *ferr);


int
fstyp_mod_init(int fd, off_t offset, fstyp_mod_handle_t *handle)
{
	fstyp_hsfs_t	*h = (fstyp_hsfs_t *)handle;

	if (offset != 0) {
		return (FSTYP_ERR_OFFSET);
	}

	if ((h = calloc(1, sizeof (fstyp_hsfs_t))) == NULL) {
		return (FSTYP_ERR_NOMEM);
	}
	h->fd = fd;

	*handle = (fstyp_mod_handle_t)h;
	return (0);
}

void
fstyp_mod_fini(fstyp_mod_handle_t handle)
{
	fstyp_hsfs_t	*h = (fstyp_hsfs_t *)handle;

	if (h->attr == NULL) {
		nvlist_free(h->attr);
		h->attr = NULL;
	}
	free(h);
}

int
fstyp_mod_ident(fstyp_mod_handle_t handle)
{
	fstyp_hsfs_t *h = (fstyp_hsfs_t *)handle;

	return (is_hsfs(h));
}

int
fstyp_mod_get_attr(fstyp_mod_handle_t handle, nvlist_t **attrp)
{
	fstyp_hsfs_t	*h = (fstyp_hsfs_t *)handle;
	int error;

	if (h->attr == NULL) {
		if (nvlist_alloc(&h->attr, NV_UNIQUE_NAME_TYPE, 0)) {
			return (FSTYP_ERR_NOMEM);
		}
		if ((error = get_attr(h)) != 0) {
			nvlist_free(h->attr);
			h->attr = NULL;
			return (error);
		}
	}

	*attrp = h->attr;
	return (0);
}

/* ARGSUSED */
int
fstyp_mod_dump(fstyp_mod_handle_t handle, FILE *fout, FILE *ferr)
{
	int		error;
	nvlist_t	*attr;
	nvpair_t	*elem = NULL;
	char		*str_value;
	uint64_t	uint64_value;
	char		*name;

	if ((error = fstyp_mod_get_attr(handle, &attr)) != 0) {
		return (error);
	}
	while ((elem = nvlist_next_nvpair(attr, elem)) != NULL) {
		/* format is special */
		if (strcmp(nvpair_name(elem), "format") == 0) {
			(void) nvpair_value_string(elem, &str_value);
			if (strcmp(str_value,
			    "ISO 9660 with UNIX extension") == 0) {
				(void) fprintf(fout,
				    "CD-ROM is in ISO 9660 format with"
				    " UNIX extension\n");
			} else {
				(void) fprintf(fout, "CD-ROM is in %s"
				    " format\n", str_value);
			}
			continue;
		}
		if ((name = get_old_name(nvpair_name(elem))) == NULL) {
			continue;
		}
		if (nvpair_type(elem) == DATA_TYPE_STRING) {
			(void) nvpair_value_string(elem, &str_value);
			(void) fprintf(fout, "%s: %s\n", name, str_value);
		} else if (nvpair_type(elem) == DATA_TYPE_UINT64) {
			(void) nvpair_value_uint64(elem, &uint64_value);
			(void) fprintf(fout, "%s %llu\n",
			    name, (u_longlong_t)uint64_value);
		}
	}

	return (0);
}

static char *
get_old_name(char *new)
{
	static char	*map[] = {
		"system_id",		"System id",
		"volume_id",		"Volume id",
		"volume_set_id",	"Volume set id",
		"publisher_id",		"Publisher id",
		"data_preparer_id",	"Data preparer id",
		"application_id",	"Application id",
		"copyright_file_id",	"Copyright File id",
		"abstract_file_id",	"Abstract File id",
		"bibliographic_file_id", "Bibliographic File id",
		"volume_set_size",	"Volume set size is",
		"volume_set_sequence_number", "Volume set sequence number is",
		"logical_block_size",	"Logical block size is",
		"volume_size",		"Volume size is"
	};
	int	i;
	char	*old = NULL;

	for (i = 0; i < NELEM(map) / 2; i++) {
		if (strcmp(new, map[i * 2]) == 0) {
			old = map[i * 2 + 1];
			break;
		}
	}
	return (old);
}

/*
 * findhsvol: check if the disk is in high sierra format
 *            return(1) if found, (0) otherwise
 *	      if found, volp will point to the descriptor
 *
 */
static int
findhsvol(fstyp_hsfs_t *h, char *volp)
{
	int secno;
	int i;
	int err;

	secno = HS_VOLDESC_SEC;
	if ((err = GETCDSECTOR(h, volp, secno++, 1)) != 0) {
		return (err);
	}
	while (HSV_DESC_TYPE(volp) != VD_EOV) {
		for (i = 0; i < HSV_ID_STRLEN; i++)
			if (HSV_STD_ID(volp)[i] != HSV_ID_STRING[i])
				goto cantfind;
		if (HSV_STD_VER(volp) != HSV_ID_VER)
			goto cantfind;
		switch (HSV_DESC_TYPE(volp)) {
		case VD_SFS:
			h->hs_pvd_sec_no = secno-1;
			return (0);
		case VD_EOV:
			goto cantfind;
		}
		if ((err = GETCDSECTOR(h, volp, secno++, 1)) != 0) {
			return (err);
		}
	}
cantfind:
	return (FSTYP_ERR_NO_MATCH);
}

/*
 * findisovol: check if the disk is in ISO 9660 format
 *            return(1) if found, (0) otherwise
 *	      if found, volp will point to the descriptor
 *
 */
static int
findisovol(fstyp_hsfs_t *h, char *volp)
{
	int secno;
	int i;
	int err;

	secno = ISO_VOLDESC_SEC;
	if ((err = GETCDSECTOR(h, volp, secno++, 1)) != 0) {
		return (err);
	}
	while (ISO_DESC_TYPE(volp) != ISO_VD_EOV) {
		for (i = 0; i < ISO_ID_STRLEN; i++)
			if (ISO_STD_ID(volp)[i] != ISO_ID_STRING[i])
				goto cantfind;
		if (ISO_STD_VER(volp) != ISO_ID_VER)
			goto cantfind;
		switch (ISO_DESC_TYPE(volp)) {
		case ISO_VD_PVD:
			h->iso_pvd_sec_no = secno-1;
			return (0);
		case ISO_VD_EOV:
			goto cantfind;
		}
		if ((err = GETCDSECTOR(h, volp, secno++, 1)) != 0) {
			return (err);
		}
	}
cantfind:
	return (FSTYP_ERR_NO_MATCH);
}

/*
 * findunixvol: check if the disk is in UNIX extension format
 *            return(1) if found, (0) otherwise
 *	      if found, volp will point to the descriptor
 *
 */
static int
findunixvol(fstyp_hsfs_t *h, char *volp)
{
	int secno;
	int i;
	int err;

	secno = ISO_VOLDESC_SEC;
	if ((err = GETCDSECTOR(h, volp, secno++, 1)) != 0) {
		return (err);
	}
	while (ISO_DESC_TYPE(volp) != ISO_VD_EOV) {
		for (i = 0; i < ISO_ID_STRLEN; i++)
			if (ISO_STD_ID(volp)[i] != ISO_ID_STRING[i])
				goto cantfind;
		if (ISO_STD_VER(volp) != ISO_ID_VER)
			goto cantfind;
		switch (ISO_DESC_TYPE(volp)) {
		case ISO_VD_UNIX:
			h->unix_pvd_sec_no = secno-1;
			return (0);
		case ISO_VD_EOV:
			goto cantfind;
		}
		if ((err = GETCDSECTOR(h, volp, secno++, 1)) != 0) {
			return (err);
		}
	}
cantfind:
	return (FSTYP_ERR_NO_MATCH);
}

static int
ckvoldesc(fstyp_hsfs_t *h, int *cd_type)
{
	int	err;

	if ((err = findhsvol(h, h->hs_buf)) == 0) {
		*cd_type = 0;
	} else if ((err = findisovol(h, h->iso_buf)) == 0) {
		if (findunixvol(h, h->unix_buf) == 0) {
			*cd_type = 2;
		} else {
			*cd_type = 1;
		}
	} else {
		*cd_type = -1;
	}

	return (err);
}

static int
is_hsfs(fstyp_hsfs_t *h)
{
#ifdef CDROMREADOFFSET
	int err;

	if (rdev_is_a_cd(h->fd)) {
		err = ioctl(h->fd, CDROMREADOFFSET, &h->cdroff);
		if (err == -1)
			/*
			 *  This device doesn't support this ioctl.
			 *  That's OK.
			 */
			h->cdroff = 0;
	}
#endif
	/* check volume descriptor */
	return (ckvoldesc(h, &h->cd_type));
}

#define	ADD_STRING(h, name, value) \
	if (nvlist_add_string(h->attr, name, value) != 0) { \
		return (FSTYP_ERR_NOMEM); \
	}

#define	ADD_UINT64(h, name, value) \
	if (nvlist_add_uint64(h->attr, name, value) != 0) { \
		return (FSTYP_ERR_NOMEM); \
	}

#define	ADD_BOOL(h, name, value) \
	if (nvlist_add_boolean_value(h->attr, name, value) != 0) { \
		return (FSTYP_ERR_NOMEM); \
	}

static int
get_attr(fstyp_hsfs_t *h)
{
	char *sysid;
	char *volid;
	char *volsetid;
	char *pubid;
	char *prepid;
	char *applid;
	char *copyfile;
	char *absfile;
	char *bibfile;
	int volsetsize;
	int volsetseq;
	int blksize;
	int volsize;
	char s[256];

	switch (h->cd_type) {
	case 0:
		ADD_STRING(h, "format", "High Sierra");
		ADD_STRING(h, "gen_version", "High Sierra");
		sysid = (char *)HSV_sys_id(h->hs_buf);
		volid = (char *)HSV_vol_id(h->hs_buf);
		volsetid = (char *)HSV_vol_set_id(h->hs_buf);
		pubid = (char *)HSV_pub_id(h->hs_buf);
		prepid = (char *)HSV_prep_id(h->hs_buf);
		applid = (char *)HSV_appl_id(h->hs_buf);
		copyfile = (char *)HSV_copyr_id(h->hs_buf);
		absfile = (char *)HSV_abstr_id(h->hs_buf);
		bibfile = NULL;
		volsetsize = HSV_SET_SIZE(h->hs_buf);
		volsetseq = HSV_SET_SEQ(h->hs_buf);
		blksize = HSV_BLK_SIZE(h->hs_buf);
		volsize = HSV_VOL_SIZE(h->hs_buf);
		break;
	case 1:
		ADD_STRING(h, "format", "ISO 9660");
		ADD_STRING(h, "gen_version", "ISO 9660");
		sysid = (char *)ISO_sys_id(h->iso_buf);
		volid = (char *)ISO_vol_id(h->iso_buf);
		volsetid = (char *)ISO_vol_set_id(h->iso_buf);
		pubid = (char *)ISO_pub_id(h->iso_buf);
		prepid = (char *)ISO_prep_id(h->iso_buf);
		applid = (char *)ISO_appl_id(h->iso_buf);
		copyfile = (char *)ISO_copyr_id(h->iso_buf);
		absfile = (char *)ISO_abstr_id(h->iso_buf);
		bibfile = (char *)ISO_bibli_id(h->iso_buf);
		volsetsize = ISO_SET_SIZE(h->iso_buf);
		volsetseq = ISO_SET_SEQ(h->iso_buf);
		blksize = ISO_BLK_SIZE(h->iso_buf);
		volsize = ISO_VOL_SIZE(h->iso_buf);
		break;
	case 2:
		ADD_STRING(h, "format", "ISO 9660 with UNIX extension");
		ADD_STRING(h, "gen_version", "ISO 9660 with UNIX extension");
		sysid = (char *)ISO_sys_id(h->unix_buf);
		volid = (char *)ISO_vol_id(h->unix_buf);
		volsetid = (char *)ISO_vol_set_id(h->unix_buf);
		pubid = (char *)ISO_pub_id(h->unix_buf);
		prepid = (char *)ISO_prep_id(h->unix_buf);
		applid = (char *)ISO_appl_id(h->unix_buf);
		copyfile = (char *)ISO_copyr_id(h->unix_buf);
		absfile = (char *)ISO_abstr_id(h->unix_buf);
		bibfile = (char *)ISO_bibli_id(h->unix_buf);
		volsetsize = ISO_SET_SIZE(h->unix_buf);
		volsetseq = ISO_SET_SEQ(h->unix_buf);
		blksize = ISO_BLK_SIZE(h->unix_buf);
		volsize = ISO_VOL_SIZE(h->unix_buf);
		break;
	default:
		return (FSTYP_ERR_NO_MATCH);
	}

	copy_string(s, sysid, 32);
	ADD_STRING(h, "system_id", s);
	copy_string(s, volid, 32);
	ADD_STRING(h, "volume_id", s);
	ADD_STRING(h, "gen_volume_label", s);
	copy_string(s, volsetid, 128);
	ADD_STRING(h, "volume_set_id", s);
	copy_string(s, pubid, 128);
	ADD_STRING(h, "publisher_id", s);
	copy_string(s, prepid, 128);
	ADD_STRING(h, "data_preparer_id", s);
	copy_string(s, applid, 128);
	ADD_STRING(h, "application_id", s);
	copy_string(s, copyfile, 37);
	ADD_STRING(h, "copyright_file_id", s);
	copy_string(s, absfile, 37);
	ADD_STRING(h, "abstract_file_id", s);
	copy_string(s, bibfile, 37);
	ADD_STRING(h, "bibliographic_file_id", s);
	ADD_UINT64(h, "volume_set_size", volsetsize);
	ADD_UINT64(h, "volume_set_sequence_number", volsetseq);
	ADD_UINT64(h, "logical_block_size", blksize);
	ADD_UINT64(h, "volume_size", volsize);
	ADD_BOOL(h, "gen_clean", B_TRUE);

	return (0);
}

static void
copy_string(char *d, char *s, int maxlen)
{
	int i;

	/* strip off trailing zeros */
	for (i = maxlen-1; i >= 0; i--) {
		if (s[i] != ' ') {
			break;
		}
	}

	maxlen = i+1;
	for (i = 0; i < maxlen; i++) {
		*d++ = s[i];
	}
	*d++ = '\0';
}

/* readdisk - read from cdrom image file */
static int
getdisk(fstyp_hsfs_t *h, char *buf, int daddr, int size)
{
	if (lseek(h->fd, daddr, L_SET) == -1) {
		return (FSTYP_ERR_IO);
	}
	if (read(h->fd, buf, size) != size) {
		return (FSTYP_ERR_IO);
	}
	return (0);
}

/*
 * rdev_is_a_cd  - return TRUE if the raw device identified by
 *		      a file descriptor is a CDROM device.
 *
 *		      return FALSE if the device can't be accessed
 *		      or is not a CDROM.
 */
static int
rdev_is_a_cd(int rdevfd)
{
	struct dk_cinfo dkc;

	if (ioctl(rdevfd, DKIOCINFO, &dkc) < 0)
		return (0);
	if (dkc.dki_ctype == DKC_CDROM)
		return (1);
	else
		return (0);
}
