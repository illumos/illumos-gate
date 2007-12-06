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
 *
 * eftwrite.c -- routines for writing .eft files
 *
 * this module emits the table resulting from compilation of the
 * source files.  this code done nothing unless the -o option
 * was given on the command line.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include "out.h"
#include "stats.h"
#include "stable.h"
#include "lut.h"
#include "tree.h"
#include "eft.h"
#include "eftwrite.h"
#include "esclex.h"
#include "version.h"
#include "ptree.h"

/* for uintX_t, htonl(), etc */
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

extern char Args[];

static struct stats *Outbytes;

static int Identlen;
static int Dictlen;

void
eftwrite_init(void)
{
	Outbytes = stats_new_counter("eftwrite.total", "bytes written", 1);
}

/*ARGSUSED*/
static void
ident_lencalc(const char *s, void *rhs, void *arg)
{
	Identlen += strlen(s) + 1;
}

/*ARGSUSED*/
static void
dict_lencalc(const char *s, void *rhs, void *arg)
{
	Dictlen += strlen(s) + 1;
}

/*ARGSUSED*/
static void
ident_printer(const char *s, void *rhs, void *arg)
{
	FILE *fp = (FILE *)arg;

	fwrite(s, strlen(s) + 1, 1, fp);
}

/*ARGSUSED*/
static void
dict_printer(const char *s, void *rhs, void *arg)
{
	FILE *fp = (FILE *)arg;

	fwrite(s, strlen(s) + 1, 1, fp);
}

void
eftwrite(const char *fname)
{
	FILE *fp;
	FILE *tfp;
	struct eftheader hdr;
#define	BUFLEN	8192
	char buf[BUFLEN];
	int cc;

	if ((tfp = tmpfile()) == NULL)
		out(O_DIE|O_SYS, "cannot create temporary file");

	/* XXX switch stdout to tfp temporarily */
	/* XXX for now */
	out_altfp(tfp);
	ptree(O_ALTFP, tree_root(NULL), 0, 1);

	rewind(tfp);

	lut_walk(Ident, (lut_cb)ident_lencalc, (void *)0);
	lut_walk(Dicts, (lut_cb)dict_lencalc, (void *)0);

	bzero(&hdr, sizeof (hdr));
	hdr.magic = EFT_HDR_MAGIC;
	hdr.major = EFT_HDR_MAJOR;
	hdr.minor = EFT_HDR_MINOR;
	hdr.cmajor = VERSION_MAJOR;
	hdr.cminor = VERSION_MINOR;
	hdr.identlen = Identlen;
	hdr.dictlen = Dictlen;
	buf[BUFLEN - 1] = '\0';

#ifdef DEBUG
	(void) snprintf(hdr.comment, EFT_HDR_MAXCOMMENT,
	    "Built using esc-%d.%d\tArgs: \"%s\"\n", VERSION_MAJOR,
	    VERSION_MINOR, Args);
#else
	(void) snprintf(hdr.comment, EFT_HDR_MAXCOMMENT,
	    "Built using esc-%d.%d\n", VERSION_MAJOR, VERSION_MINOR);
#endif

	if ((fp = fopen(fname, "w")) == NULL)
		out(O_DIE|O_SYS, "can't open output file: %s", fname);

	while ((cc = fread(buf, 1, BUFLEN, tfp)) > 0) {
		char *ptr;

		for (ptr = buf; ptr < &buf[cc]; ptr++)
			hdr.csum += (uint32_t)*ptr;
	}
	if (ferror(tfp))
		out(O_DIE|O_SYS, "fread on tmpfile");
	rewind(tfp);

	hdr.magic = htonl(hdr.magic);
	hdr.major = htons(hdr.major);
	hdr.minor = htons(hdr.minor);
	hdr.cmajor = htons(hdr.cmajor);
	hdr.cminor = htons(hdr.cminor);
	hdr.identlen = htonl(hdr.identlen);
	hdr.dictlen = htonl(hdr.dictlen);
	hdr.csum = htonl(hdr.csum);

	fwrite(&hdr, sizeof (hdr), 1, fp);
	if (ferror(fp))
		out(O_DIE|O_SYS, "%s: can't write header", fname);
	stats_counter_add(Outbytes, sizeof (hdr));

	lut_walk(Ident, (lut_cb)ident_printer, (void *)fp);
	stats_counter_add(Outbytes, Identlen);
	lut_walk(Dicts, (lut_cb)dict_printer, (void *)fp);
	stats_counter_add(Outbytes, Dictlen);

	while ((cc = fread(buf, 1, BUFLEN, tfp)) > 0) {
		char *ptr;

		for (ptr = buf; ptr < &buf[cc]; ptr++)
			*ptr = ~((unsigned char)*ptr);
		if (cc != fwrite(buf, 1, cc, fp) || ferror(fp))
			out(O_DIE|O_SYS, "fwrite on %s", fname);
		stats_counter_add(Outbytes, cc);
	}
	if (ferror(tfp))
		out(O_DIE|O_SYS, "fread on tmpfile");
	fclose(tfp);
	fclose(fp);
}
