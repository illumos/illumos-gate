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
 *
 * eftread.c -- routines for reading .eft files
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <alloca.h>
#include "out.h"
#include "stable.h"
#include "lut.h"
#include "tree.h"
#include "eft.h"
#include "eftread.h"
#include "esclex.h"
#include "version.h"
#include "ptree.h"

/* for uintX_t, htonl(), etc */
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

#ifndef MIN
#define	MIN(x, y) ((x) <= (y) ? (x) : (y))
#endif

static int Showheader;

/*
 * eftread_showheader -- set showheader flag
 *
 */
void
eftread_showheader(int newval)
{
	Showheader = newval;
}

/*
 * eftread_fopen -- fopen an EFT file for reading
 *
 */

FILE *
eftread_fopen(const char *fname, char *idbuf, size_t idbufsz)
{
	FILE *fp;
	FILE *tfp;
	struct eftheader hdr;
#define	BUFLEN	8192
	char buf[BUFLEN];
	int cc;
	uint32_t csum = 0;
	char *ptr;

	if ((ptr = strrchr(fname, '.')) == NULL || strcmp(ptr, ".eft") != 0) {
		out(O_ERR, "%s: not a valid EFT (bad extension)", fname);
		return (NULL);
	}

	if ((fp = fopen(fname, "r")) == NULL) {
		out(O_ERR|O_SYS, "%s", fname);
		return (NULL);
	}

	if (fread(&hdr, 1, sizeof (hdr), fp) < sizeof (hdr)) {
		(void) fclose(fp);
		out(O_ERR, "%s: not a valid EFT (too short)", fname);
		return (NULL);
	}
	hdr.magic = ntohl(hdr.magic);
	hdr.major = ntohs(hdr.major);
	hdr.minor = ntohs(hdr.minor);
	hdr.cmajor = ntohs(hdr.cmajor);
	hdr.cminor = ntohs(hdr.cminor);
	hdr.identlen = ntohl(hdr.identlen);
	hdr.dictlen = ntohl(hdr.dictlen);
	hdr.csum = ntohl(hdr.csum);

	if (Showheader)
		out(O_VERB, "%s: magic %x EFT version %d.%d esc version %d.%d",
		    fname, hdr.magic, hdr.major, hdr.minor,
		    hdr.cmajor, hdr.cminor);

	if (hdr.magic != EFT_HDR_MAGIC) {
		(void) fclose(fp);
		out(O_ERR, "%s: not a valid EFT (bad magic)", fname);
		return (NULL);
	}

	if (hdr.major != EFT_HDR_MAJOR || hdr.minor > EFT_HDR_MINOR) {
		(void) fclose(fp);
		out(O_ERR, "%s is version %d.%d, "
		    "this program supports up to %d.%d", fname,
		    hdr.major, hdr.minor, EFT_HDR_MAJOR, EFT_HDR_MINOR);
		return (NULL);
	}

	bzero(idbuf, idbufsz);
	if (hdr.identlen != 0) {
		long npos = ftell(fp) + (long)hdr.identlen; /* after ident */
		size_t rsz = MIN(hdr.identlen, idbufsz - 1);

		if (fread(idbuf, 1, rsz, fp) != rsz)
			out(O_DIE|O_SYS, "%s: fread", fname);
		if (fseek(fp, npos, SEEK_SET) == -1)
			out(O_DIE|O_SYS, "%s: fseek", fname);
	}

	if (hdr.dictlen && (hdr.dictlen < 2 || hdr.dictlen > 1000)) {
		(void) fclose(fp);
		out(O_ERR, "%s: bad dictlen: %d", fname, hdr.dictlen);
		return (NULL);
	}

	/* read in dict strings */
	if (hdr.dictlen) {
		char *dbuf = alloca(hdr.dictlen);
		char *dptr;

		if ((cc = fread(dbuf, 1, hdr.dictlen, fp)) != hdr.dictlen)
			out(O_DIE|O_SYS, "short fread on %s (dictlen %d)",
			    fname, hdr.dictlen);

		/* work from end of string array backwards, finding names */
		for (dptr = &dbuf[hdr.dictlen - 2]; dptr > dbuf; dptr--)
			if (*dptr == '\0') {
				/* found separator, record string */
				Dicts = lut_add(Dicts,
				    (void *)stable(dptr + 1), (void *)0, NULL);
			}
		/* record the first string */
		Dicts = lut_add(Dicts,
		    (void *)stable(dptr), (void *)0, NULL);
	}

	if ((tfp = tmpfile()) == NULL)
		out(O_DIE|O_SYS, "cannot create temporary file");

	while ((cc = fread(buf, 1, BUFLEN, fp)) > 0) {
		char *ptr;

		for (ptr = buf; ptr < &buf[cc]; ptr++) {
			*ptr = ~((unsigned char)*ptr);
			csum += (uint32_t)*ptr;
		}
		if (cc != fwrite(buf, 1, cc, tfp) || ferror(tfp))
			out(O_DIE|O_SYS, "fwrite on tmpfile");
	}
	if (ferror(fp))
		out(O_DIE|O_SYS, "fread on %s", fname);
	(void) fclose(fp);

	if (hdr.csum != csum) {
		out(O_ERR, "%s: bad checksum (%x != %x)", fname,
		    hdr.csum, csum);
		(void) fclose(tfp);
		return (NULL);
	}

	if (Showheader) {
		int len = strlen(hdr.comment);
		if (len > 0 && hdr.comment[len - 1] == '\n')
			hdr.comment[len - 1] = '\0';
		out(O_OK, "%s:\n\t%s", fname, hdr.comment);
	}

	rewind(tfp);

	return (tfp);
}
