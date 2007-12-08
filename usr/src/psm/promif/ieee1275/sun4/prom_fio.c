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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

int
prom_fopen(ihandle_t fsih, char *path)
{
	cell_t ci[10];
	size_t len;

#ifdef PROM_32BIT_ADDRS
	char *opath = NULL;

	if ((uintptr_t)path > (uint32_t)-1) {
		opath = path;
		len = prom_strlen(opath) + 1; /* include terminating NUL */
		path = promplat_alloc(len);
		if (path == NULL)
			return (0);
		(void) prom_strcpy(path, opath);
	}
#endif
	len = prom_strlen(path);

	promif_preprom();
	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)4;			/* #argument cells */
	ci[2] = (cell_t)3;			/* #result cells */
	ci[3] = p1275_ptr2cell("open-file");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(fsih);	/* Arg2: fs ihandle */
	ci[5] = p1275_uint2cell(len);		/* Arg3: Len */
	ci[6] = p1275_ptr2cell(path);		/* Arg4: Pathname */

	(void) p1275_cif_handler(&ci);

	promif_postprom();

#ifdef PROM_32BIT_ADDRS
	if (opath != NULL)
		promplat_free(path, len + 1);
#endif

	if (ci[7] != 0)				/* Catch result */
		return (-1);

	if (ci[8] == 0)				/* Res1: failed */
		return (-1);

	return (p1275_cell2int(ci[9]));		/* Res2: fd */
}


int
prom_fseek(ihandle_t fsih, int fd, unsigned long long offset)
{
	cell_t ci[10];

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)4;			/* #argument cells */
	ci[2] = (cell_t)3;			/* #result cells */
	ci[3] = p1275_ptr2cell("seek-file");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(fsih);	/* Arg2: fs ihandle */
	ci[5] = p1275_int2cell(fd);		/* Arg3: file desc */
	ci[6] = p1275_ull2cell_low(offset);	/* Arg4: Offset */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	if (ci[7] != 0)				/* Catch result */
		return (-1);

	if (ci[8] == 0)				/* Res1: failed */
		return (-1);

	return (p1275_cell2int(ci[9]));		/* Res2: off */
}


int
prom_fread(ihandle_t fsih, int fd, caddr_t buf, size_t len)
{
	cell_t ci[10];
#ifdef PROM_32BIT_ADDRS
	caddr_t obuf = NULL;

	if ((uintptr_t)buf > (uint32_t)-1) {
		obuf = buf;
		buf = promplat_alloc(len);
		if (buf == NULL)
			return (-1);
	}
#endif

	promif_preprom();

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)5;			/* #argument cells */
	ci[2] = (cell_t)2;			/* #result cells */
	ci[3] = p1275_ptr2cell("read-file");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(fsih);	/* Arg2: fs ihandle */
	ci[5] = p1275_int2cell(fd);		/* Arg3: file desc */
	ci[6] = p1275_uint2cell(len);		/* Arg4: buffer length */
	ci[7] = p1275_ptr2cell(buf);		/* Arg5: buffer address */

	(void) p1275_cif_handler(&ci);

	promif_postprom();

#ifdef PROM_32BIT_ADDRS
	if (obuf != NULL) {
		promplat_bcopy(buf, obuf, len);
		promplat_free(buf, len);
	}
#endif

	if (ci[8] != 0)				/* Catch result */
		return (-1);

	return (p1275_cell2int(ci[9]));		/* Res2: actual length */
}

int
prom_fsize(ihandle_t fsih, int fd, size_t *size)
{
	cell_t ci[8];

	promif_preprom();

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)3;			/* #argument cells */
	ci[2] = (cell_t)2;			/* #result cells */
	ci[3] = p1275_ptr2cell("size-file");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(fsih);	/* Arg2: fs ihandle */
	ci[5] = p1275_int2cell(fd);		/* Arg3: file desc */

	(void) p1275_cif_handler(&ci);

	promif_postprom();

	if (ci[6] != 0)				/* Catch result */
		return (-1);

	*size = p1275_cell2uint(ci[7]);		/* Res2: size */
	return (0);
}


int
prom_compinfo(ihandle_t fsih, int fd, int *iscmp, size_t *fsize, size_t *bsize)
{
	cell_t ci[10];

	promif_preprom();

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)3;			/* #argument cells */
	ci[2] = (cell_t)4;			/* #result cells */
	ci[3] = p1275_ptr2cell("cinfo-file");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(fsih);	/* Arg2: fs ihandle */
	ci[5] = p1275_int2cell(fd);		/* Arg3: file desc */

	(void) p1275_cif_handler(&ci);

	promif_postprom();

	if (ci[6] != 0)				/* Catch result */
		return (-1);

	*iscmp = p1275_cell2int(ci[7]);		/* Res2: iscmp */
	*fsize = p1275_cell2uint(ci[8]);	/* Res3: fsize */
	*bsize = p1275_cell2uint(ci[9]);	/* Res4: bsize */
	return (0);
}

void
prom_fclose(ihandle_t fsih, int fd)
{
	cell_t ci[7];

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)3;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_ptr2cell("close-file");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(fsih);	/* Arg2: fs ihandle */
	ci[5] = p1275_int2cell(fd);		/* Arg3: file desc */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

}
