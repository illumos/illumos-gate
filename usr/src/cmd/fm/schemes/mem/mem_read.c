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

/*
 * Retrieval of the DIMM serial number from data encoded in the SPD and
 * SEEPROM formats.
 */

#include <mem_spd.h>
#include <mem_seeprom.h>
#include <mem.h>

#include <fm/fmd_fmri.h>

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <strings.h>
#include <sys/byteorder.h>
#include <sys/stat.h>
#include <sys/types.h>

#define	BUFSIZ_SPD	256
#define	BUFSIZ_SEEPROM	8192

/*
 * SEEPROMs are composed of self-describing containers.  The first container,
 * starting at offset 0, is r/w.  The second container, starting at 0x1800, is
 * r/o, and contains identification information supplied by the manufacturer.
 */
#define	SEEPROM_OFFSET_RO	0x1800

static int
mem_get_spd_serid(const char *buf, size_t bufsz, char *serid, size_t seridsz)
{
	static const char hex_digits[] = "0123456789ABCDEF";
	spd_data_t *spd = (spd_data_t *)buf;
	char *c;
	int i;

	if (bufsz < sizeof (spd_data_t))
		return (fmd_fmri_set_errno(EINVAL));

	if (seridsz < sizeof (spd->asmb_serial_no) * 2 + 1)
		return (fmd_fmri_set_errno(EINVAL));

	for (c = serid, i = 0; i < sizeof (spd->asmb_serial_no); i++) {
		*c++ = hex_digits[spd->asmb_serial_no[i] >> 4];
		*c++ = hex_digits[spd->asmb_serial_no[i] & 0xf];
	}
	*c = '\0';

	return (0);
}

static void *
seeprom_seg_lookup(const char *buf, size_t bufsz, char *segname, size_t *segszp)
{
	seeprom_container_t *sc;
	seeprom_seg_t *segp, seg;
	int sidx;

	if (strlen(segname) != sizeof (seg.sees_name))
		return (NULL);

	sc = (seeprom_container_t *)(buf + SEEPROM_OFFSET_RO);

	/* Validate sc size then dereference it */
	if (bufsz < SEEPROM_OFFSET_RO + sizeof (seeprom_container_t) ||
	    bufsz < SEEPROM_OFFSET_RO + sizeof (seeprom_container_t) +
	    sc->seec_contsz)
		return (NULL);

	if (sc->seec_tag == 0 || sc->seec_contsz == 0 ||
	    sc->seec_nsegs == 0)
		return (NULL);

	for (sidx = 0; sidx < sc->seec_nsegs; sidx++) {
		/* LINTED - pointer alignment */
		segp = ((seeprom_seg_t *)(sc + 1)) + sidx;

		bcopy(segp, &seg, sizeof (seeprom_seg_t));
		seg.sees_segoff = ntohs(seg.sees_segoff);
		seg.sees_seglen = ntohs(seg.sees_seglen);

		if (bufsz < seg.sees_segoff + seg.sees_seglen)
			return (NULL);

		if (strncmp(segname, seg.sees_name,
		    sizeof (seg.sees_name)) == 0) {
			*segszp = seg.sees_seglen;
			return ((void *)(buf + seg.sees_segoff));
		}

	}

	return (NULL);
}

static int
mem_get_seeprom_serid(const char *buf, size_t bufsz, char *serid,
    size_t seridsz)
{
	seeprom_seg_sd_t *sd;
	size_t segsz;

	if (seridsz < sizeof (sd->seesd_sun_sno) + 1)
		return (fmd_fmri_set_errno(EINVAL));

	if ((sd = seeprom_seg_lookup(buf, bufsz, "SD", &segsz)) == NULL)
		return (fmd_fmri_set_errno(EINVAL));

	if (segsz < sizeof (seeprom_seg_sd_t))
		return (fmd_fmri_set_errno(EINVAL));

	bcopy(sd->seesd_sun_sno, serid, sizeof (sd->seesd_sun_sno));
	serid[sizeof (sd->seesd_sun_sno)] = '\0';

	return (0);
}

int
mem_get_serid(const char *device, char *serid, size_t seridsz)
{
	char buf[8192];
	int fd;
	ssize_t sz;

	if ((fd = open(device, O_RDONLY)) < 0)
		return (-1); /* errno is set for us */

	if ((sz = read(fd, buf, sizeof (buf))) < 0) {
		int err = errno;
		(void) close(fd);
		return (fmd_fmri_set_errno(err));
	}

	(void) close(fd);

	switch (sz) {
	case BUFSIZ_SPD:
		return (mem_get_spd_serid(buf, BUFSIZ_SPD, serid, seridsz));
	case BUFSIZ_SEEPROM:
		return (mem_get_seeprom_serid(buf, BUFSIZ_SEEPROM, serid,
		    seridsz));
	default:
		return (fmd_fmri_set_errno(EINVAL));
	}
}
