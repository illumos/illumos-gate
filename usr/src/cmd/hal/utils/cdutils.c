/***************************************************************************
 *
 * cdutils.c : CD/DVD utilities
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/


#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/scsi/impl/uscsi.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/dkio.h>
#include <libintl.h>

#include <logger.h>

#include "cdutils.h"

#define	RQLEN	32
#define SENSE_KEY(rqbuf)        (rqbuf[2])      /* scsi error category */
#define ASC(rqbuf)              (rqbuf[12])     /* additional sense code */
#define ASCQ(rqbuf)             (rqbuf[13])     /* ASC qualifier */

#define	GET16(a) (((a)[0] << 8) | (a)[1])
#define	GET32(a) (((a)[0] << 24) | ((a)[1] << 16) | ((a)[2] << 8) | (a)[3])

#define	CD_USCSI_TIMEOUT	60

void
uscsi_cmd_init(struct uscsi_cmd *scmd, char *cdb, int cdblen)
{
	bzero(scmd, sizeof (*scmd));
	bzero(cdb, cdblen);
	scmd->uscsi_cdb = cdb;
}

int
uscsi(int fd, struct uscsi_cmd *scmd)
{
	char		rqbuf[RQLEN];
	int		ret;
	int		f, i, retries, total_retries;
	int		max_retries = 20;

	f = scmd->uscsi_flags;
	scmd->uscsi_flags |= USCSI_RQENABLE;
	scmd->uscsi_rqlen = RQLEN;
	scmd->uscsi_rqbuf = rqbuf;

	for (retries = 0; retries < max_retries; retries++) {
		scmd->uscsi_status = 0;
		memset(rqbuf, 0, RQLEN);

		ret = ioctl(fd, USCSICMD, scmd);

		if ((ret == 0) && (scmd->uscsi_status == 2)) {
			ret = -1;
			errno = EIO;
		}
		if ((ret < 0) && (scmd->uscsi_status == 2)) {
			/*
			 * The drive is not ready to recieve commands but
			 * may be in the process of becoming ready.
			 * sleep for a short time then retry command.
			 * SENSE/ASC = 2/4 : not ready
			 * ASCQ = 0  Not Reportable.
			 * ASCQ = 1  Becoming ready.
			 * ASCQ = 4  FORMAT in progress.
			 * ASCQ = 7  Operation in progress.
			 */
			if ((SENSE_KEY(rqbuf) == 2) && (ASC(rqbuf) == 4) &&
			    ((ASCQ(rqbuf) == 0) || (ASCQ(rqbuf) == 1) ||
			    (ASCQ(rqbuf) == 4)) || (ASCQ(rqbuf) == 7)) {
				total_retries++;
				sleep(1);
				continue;
			}

			/*
			 * Device is not ready to transmit or a device reset
			 * has occurred. wait for a short period of time then
			 * retry the command.
			 */
			if ((SENSE_KEY(rqbuf) == 6) && ((ASC(rqbuf) == 0x28) ||
			    (ASC(rqbuf) == 0x29))) {
				sleep(1);
				total_retries++;
				continue;
			}
			/*
			 * Blank Sense, we don't know what the error is or if
			 * the command succeeded, Hope for the best. Some
			 * drives return blank sense periodically and will
			 * fail if this is removed.
			 */
			if ((SENSE_KEY(rqbuf) == 0) && (ASC(rqbuf) == 0) &&
			    (ASCQ(rqbuf) == 0)) {
				ret = 0;
				break;
			}

			HAL_DEBUG (("cmd: 0x%02x ret:%i status:%02x "
			    " sense: %02x ASC: %02x ASCQ:%02x\n",
			    (uchar_t)scmd->uscsi_cdb[0], ret,
			    scmd->uscsi_status,
			    (uchar_t)SENSE_KEY(rqbuf),
			    (uchar_t)ASC(rqbuf), (uchar_t)ASCQ(rqbuf)));
		}

		break;
	}

	if (retries) {
		HAL_DEBUG (("total retries: %d\n", total_retries));
	}

	/* do not leak address from local stack and restore flags */
	scmd->uscsi_rqbuf = NULL;
	scmd->uscsi_flags = f;
	scmd->uscsi_rqlen = 0;
	return (ret);
}

int
mode_sense(int fd, uchar_t pc, int dbd, int page_len, uchar_t *buffer)
{
	struct uscsi_cmd scmd;
	char cdb[16];

	uscsi_cmd_init(&scmd, cdb, sizeof (cdb));
	scmd.uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd.uscsi_buflen = page_len;
	scmd.uscsi_bufaddr = (char *)buffer;
	scmd.uscsi_timeout = CD_USCSI_TIMEOUT;
	scmd.uscsi_cdblen = 0xa;
	scmd.uscsi_cdb[0] = 0x5a; /* MODE SENSE 10 */
	if (dbd) {
		scmd.uscsi_cdb[1] = 0x8; /* no block descriptors */
	}
	scmd.uscsi_cdb[2] = pc;
	scmd.uscsi_cdb[7] = (page_len >> 8) & 0xff;
	scmd.uscsi_cdb[8] = page_len & 0xff;

	return (uscsi(fd, &scmd) == 0);
}

/*
 * will get the mode page only i.e. will strip off the header.
 */
int
get_mode_page(int fd, int page_no, int pc, int buf_len, uchar_t *buffer, int *plen)
{
	int ret;
	uchar_t byte2;
	uchar_t buf[256];
	uint_t header_len, page_len, copy_cnt;

	byte2 = (uchar_t)(((pc << 6) & 0xC0) | (page_no & 0x3f));

	/* Ask 254 bytes only to make our IDE driver happy */
	if ((ret = mode_sense(fd, byte2, 1, 254, buf)) == 0) {
		return (0);
	}

	header_len = 8 + GET16(&buf[6]);
	page_len = buf[header_len + 1] + 2;

	copy_cnt = (page_len > buf_len) ? buf_len : page_len;
	(void) memcpy(buffer, &buf[header_len], copy_cnt);

	if (plen) {
		*plen = page_len;
	}

	return (1);
}

/* Get information about the Logical Unit's capabilities */
int
get_configuration(int fd, uint16_t feature, int bufsize, uchar_t *buf)
{
	struct uscsi_cmd scmd;
	char cdb[16];

	uscsi_cmd_init(&scmd, cdb, sizeof (cdb));
	scmd.uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd.uscsi_timeout = CD_USCSI_TIMEOUT;
	scmd.uscsi_cdb[0] = 0x46; /* GET CONFIGURATION */
	scmd.uscsi_cdb[1] = 0x2; /* request type */
	scmd.uscsi_cdb[2] = (feature >> 8) & 0xff; /* starting feature # */
	scmd.uscsi_cdb[3] = feature & 0xff;
	scmd.uscsi_cdb[7] = (bufsize >> 8) & 0xff; /* allocation length */
	scmd.uscsi_cdb[8] = bufsize & 0xff;
	scmd.uscsi_cdblen = 10;
	scmd.uscsi_bufaddr = (char *)buf;
	scmd.uscsi_buflen = bufsize;

	return (uscsi(fd, &scmd) == 0);
}

boolean_t
get_current_profile(int fd, int *profile)
{
	size_t i;
	uchar_t smallbuf[8];
	size_t buflen;
	uchar_t *bufp;
	int ret = B_FALSE;

	/*
	 * first determine amount of memory needed to hold all profiles.
	 * The first four bytes of smallbuf concatenated tell us the
	 * number of bytes of memory we need but do not take themselves
	 * into account. Therefore, add four to allocate that number
	 * of bytes.
	 */
	if (get_configuration(fd, 0, 8, &smallbuf[0])) {
		buflen = GET32(smallbuf) + 4;
		bufp = (uchar_t *)malloc(buflen);

	 	/* now get all profiles */
		if (get_configuration(fd, 0, buflen, bufp)) {
			*profile = GET16(&bufp[6]);
			ret = B_TRUE;
		}
		free(bufp);
	}

	return (ret);
}

void
walk_profiles(int fd, int (*f)(void *, int, boolean_t), void *arg)
{
	size_t i;
	uint16_t profile, current_profile;
	uchar_t smallbuf[8];
	size_t buflen;
	uchar_t *bufp;
	int ret;

	/*
	 * first determine amount of memory needed to hold all profiles.
	 * The first four bytes of smallbuf concatenated tell us the
	 * number of bytes of memory we need but do not take themselves
	 * into account. Therefore, add four to allocate that number
	 * of bytes.
	 */
	if (get_configuration(fd, 0, 8, &smallbuf[0])) {
		buflen = GET32(smallbuf) + 4;
		bufp = (uchar_t *)malloc(buflen);

	 	/* now get all profiles */
		if (get_configuration(fd, 0, buflen, bufp)) {
			current_profile = GET16(&bufp[6]);
			for (i = 8 + 4;  i < buflen; i += 4) {
				profile = GET16(&bufp[i]);
				ret = f(arg, profile, (profile == current_profile));
				if (ret == CDUTIL_WALK_STOP) {
					break;
				}
			}
		}

		free(bufp);
	}
}

/* retrieve speed list from the Write Speed Performance Descriptor Blocks
 */
void
get_write_speeds(uchar_t *page, int n, intlist_t **speeds, int *n_speeds, intlist_t **speeds_mem)
{
	uchar_t	*p = page + 2;
	int	i;
	intlist_t **nextp;
	intlist_t *current;
	boolean_t skip;

	*n_speeds = 0;
	*speeds = NULL;
	*speeds_mem = (intlist_t *)calloc(n, sizeof (intlist_t));
	if (*speeds_mem == NULL) {
		return;
	}

	for (i = 0; i < n; i++, p += 4) {
		current = &(*speeds_mem)[i];
		current->val = GET16(p);

		/* keep the list sorted */
		skip = B_FALSE;
		for (nextp = speeds; *nextp != NULL; nextp = &((*nextp)->next)) {
			if (current->val == (*nextp)->val) {
				skip = B_TRUE; /* skip duplicates */
				break;
			} else if (current->val > (*nextp)->val) {
				break;
			}
		}
		if (!skip) {
			current->next = *nextp;
			*nextp = current;
			*n_speeds++;
		}
	}
}

void
get_read_write_speeds(int fd, int *read_speed, int *write_speed,
    intlist_t **speeds, int *n_speeds, intlist_t **speeds_mem)
{
	int page_len;
	uchar_t	p[254];
	int n; /* number of write speed performance descriptor blocks */

	*read_speed = *write_speed = 0;
	*speeds = *speeds_mem = NULL;

	if (!get_mode_page(fd, 0x2A, 0, sizeof (p), p, &page_len)) {
		return;
	}

	if (page_len > 8) {
		*read_speed = GET16(&p[8]);
	}
	if (page_len > 18) {
		*write_speed = GET16(&p[18]);
	}
	if (page_len < 28) {
		printf("MMC-2\n");
		return;
	} else {
		printf("MMC-3\n");
	}

	*write_speed = GET16(&p[28]);

	if (page_len < 30) {
		return;
	}

	/* retrieve speed list */
	n = GET16(&p[30]);
	n = min(n, (sizeof (p) - 32) / 4);

	get_write_speeds(&p[32], n, speeds, n_speeds, speeds_mem);

	if (*speeds != NULL) {
		*write_speed = max(*write_speed, (*speeds)[0].val);
	}
}

boolean_t
get_disc_info(int fd, disc_info_t *di)
{
	struct uscsi_cmd scmd;
	char cdb[16];
	uint8_t	buf[32];
	int bufsize = sizeof (buf);

	bzero(buf, bufsize);
	uscsi_cmd_init(&scmd, cdb, sizeof (cdb));
	scmd.uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd.uscsi_timeout = CD_USCSI_TIMEOUT;
	scmd.uscsi_cdb[0] = 0x51; /* READ DISC INFORMATION */
	scmd.uscsi_cdb[7] = (bufsize >> 8) & 0xff; /* allocation length */
	scmd.uscsi_cdb[8] = bufsize & 0xff;
	scmd.uscsi_cdblen = 10;
	scmd.uscsi_bufaddr = (char *)buf;
	scmd.uscsi_buflen = bufsize;

	if ((uscsi(fd, &scmd)) != 0) {
		return (B_FALSE);
	}

	/*
	 * According to MMC-5 6.22.3.2, the Disc Information Length should be
	 * 32+8*(Number of OPC Tables). Some devices, like U3 sticks, return 0.
	 * Yet some drives can return less than 32. We only need the first 22.
	 */
	if (GET16(&buf[0]) < 22) {
		return (B_FALSE);
	}

	di->disc_status = buf[2] & 0x03;
	di->erasable = buf[2] & 0x10;
	if ((buf[21] != 0) && (buf[21] != 0xff)) {
		di->capacity = ((buf[21] * 60) + buf[22]) * 75;
	} else {
		di->capacity = 0;
	}

	return (B_TRUE);
}

/*
 * returns current/maximum format capacity in bytes
 */
boolean_t
read_format_capacity(int fd, uint64_t *capacity)
{
	struct uscsi_cmd scmd;
	char cdb[16];
	uint8_t	buf[32];
	int bufsize = sizeof (buf);
	uint32_t num_blocks;
	uint32_t block_len;

	bzero(buf, bufsize);
	uscsi_cmd_init(&scmd, cdb, sizeof (cdb));
	scmd.uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd.uscsi_timeout = CD_USCSI_TIMEOUT;
	scmd.uscsi_cdb[0] = 0x23; /* READ FORMAT CAPACITIRES */
	scmd.uscsi_cdb[7] = (bufsize >> 8) & 0xff; /* allocation length */
	scmd.uscsi_cdb[8] = bufsize & 0xff;
	scmd.uscsi_cdblen = 12;
	scmd.uscsi_bufaddr = (char *)buf;
	scmd.uscsi_buflen = bufsize;

	if ((uscsi(fd, &scmd)) != 0) {
		return (B_FALSE);
	}

	num_blocks = (uint32_t)(buf[4] << 24) + (buf[5] << 16) + (buf[6] << 8) + buf[7];
	block_len = (uint32_t)(buf[9] << 16) + (buf[10] << 8) + buf[11];
	*capacity = (uint64_t)num_blocks * block_len;

	return (B_TRUE);
}

boolean_t
get_media_info(int fd, struct dk_minfo *minfop)
{
	return (ioctl(fd, DKIOCGMEDIAINFO, minfop) != -1);
}

/*
 * given current profile, use the best method for determining
 * disc capacity (in bytes)
 */
boolean_t
get_disc_capacity_for_profile(int fd, int profile, uint64_t *capacity)
{
	struct dk_minfo	mi;
	disc_info_t	di;
	boolean_t	ret = B_FALSE;

	switch (profile) {
	case 0x08: /* CD-ROM */
	case 0x10: /* DVD-ROM */
		if (get_media_info(fd, &mi) && (mi.dki_capacity > 1)) {
			*capacity = mi.dki_capacity * mi.dki_lbsize;
			ret = B_TRUE;
		}
		break;
	default:
		if (read_format_capacity(fd, capacity) && (*capacity > 0)) {
			ret = B_TRUE;
		} else if (get_disc_info(fd, &di) && (di.capacity > 0)) {
			if (get_media_info(fd, &mi)) {
				*capacity = di.capacity * mi.dki_lbsize;
				ret = B_TRUE;
			}
		}
	}

	return (ret);
}

boolean_t
read_toc(int fd, int format, int trackno, int buflen, uchar_t *buf)
{
	struct uscsi_cmd scmd;
	char cdb[16];

	bzero(buf, buflen);
	uscsi_cmd_init(&scmd, cdb, sizeof (cdb));
	scmd.uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd.uscsi_timeout = CD_USCSI_TIMEOUT;
	scmd.uscsi_cdb[0] = 0x43 /* READ_TOC_CMD */;
	scmd.uscsi_cdb[2] = format & 0xf;
	scmd.uscsi_cdb[6] = trackno;
	scmd.uscsi_cdb[8] = buflen & 0xff;
	scmd.uscsi_cdb[7] = (buflen >> 8) & 0xff;
	scmd.uscsi_cdblen = 10;
	scmd.uscsi_bufaddr = (char *)buf;
	scmd.uscsi_buflen = buflen;

	if ((uscsi(fd, &scmd)) != 0) {
        	return (B_FALSE);
	}

	return (B_TRUE);
}
