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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 *  Returns 0 on error. Otherwise returns a handle.
 */
int
prom_open(char *path)
{
	cell_t ci[5];
	promif_owrap_t *ow;
#ifdef PROM_32BIT_ADDRS
	char *opath = NULL;
	size_t len;

	if ((uintptr_t)path > (uint32_t)-1) {
		opath = path;
		len = prom_strlen(opath) + 1; /* include terminating NUL */
		path = promplat_alloc(len);
		if (path == NULL)
			return (0);
		(void) prom_strcpy(path, opath);
	}
#endif

	ow = promif_preout();
	promif_preprom();
	ci[0] = p1275_ptr2cell("open");		/* Service name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_ptr2cell(path);		/* Arg1: Pathname */
	ci[4] = (cell_t)0;			/* Res1: Prime result */

	(void) p1275_cif_handler(&ci);

	promif_postprom();
	promif_postout(ow);

#ifdef PROM_32BIT_ADDRS
	if (opath != NULL)
		promplat_free(path, len);
#endif

	return (p1275_cell2int(ci[4]));		/* Res1: ihandle */
}


int
prom_seek(int fd, unsigned long long offset)
{
	cell_t ci[7];

	ci[0] = p1275_ptr2cell("seek");		/* Service name */
	ci[1] = (cell_t)3;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_uint2cell((uint_t)fd);	/* Arg1: ihandle */
	ci[4] = p1275_ull2cell_high(offset);	/* Arg2: pos.hi */
	ci[5] = p1275_ull2cell_low(offset);	/* Arg3: pos.lo */
	ci[6] = (cell_t)-1;			/* Res1: Prime result */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	return (p1275_cell2int(ci[6]));		/* Res1: actual */
}

/*ARGSUSED3*/
ssize_t
prom_read(ihandle_t fd, caddr_t buf, size_t len, uint_t startblk, char devtype)
{
	cell_t ci[7];
	promif_owrap_t *ow;
#ifdef PROM_32BIT_ADDRS
	caddr_t obuf = NULL;

	if ((uintptr_t)buf > (uint32_t)-1) {
		obuf = buf;
		buf = promplat_alloc(len);
		if (buf == NULL)
			return (-1);
	}
#endif

	ow = promif_preout();
	promif_preprom();

	ci[0] = p1275_ptr2cell("read");		/* Service name */
	ci[1] = (cell_t)3;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_size2cell((uint_t)fd);	/* Arg1: ihandle */
	ci[4] = p1275_ptr2cell(buf);		/* Arg2: buffer address */
	ci[5] = p1275_uint2cell(len);		/* Arg3: buffer length */
	ci[6] = (cell_t)-1;			/* Res1: Prime result */

	(void) p1275_cif_handler(&ci);

	promif_postprom();
	promif_postout(ow);

#ifdef PROM_32BIT_ADDRS
	if (obuf != NULL) {
		promplat_bcopy(buf, obuf, len);
		promplat_free(buf, len);
	}
#endif

	return (p1275_cell2size(ci[6]));	/* Res1: actual length */
}

/*
 * prom_write is the only prom_*() function we have to intercept
 * because all the other prom_*() io interfaces eventually call
 * into prom_write().
 */
/*ARGSUSED3*/
ssize_t
prom_write(ihandle_t fd, caddr_t buf, size_t len, uint_t startblk, char devtype)
{
	cell_t ci[7];
	promif_owrap_t *ow;
	ssize_t rlen;

#ifdef PROM_32BIT_ADDRS
	caddr_t obuf = NULL;
	static char smallbuf[256];

	ASSERT(buf);

	if ((uintptr_t)buf > (uint32_t)-1) {
		/*
		 * This is a hack for kernel message output.
		 * By avoiding calls to promplat_alloc (and
		 * using smallbuf instead) when memory is low
		 * we can print shortish kernel messages without
		 * deadlocking. smallbuf should be at least as
		 * large as the automatic buffer in
		 * prom_printf.c:_doprint()'s stack frame.
		 * promplat_alloc() can block on a mutex and so
		 * is called here before calling promif_preprom().
		 */

		if (len > sizeof (smallbuf)) {
			obuf = buf;
			buf = promplat_alloc(len);
			if (buf == NULL) {
				return (-1);
			}
			promplat_bcopy(obuf, buf, len);
		}
	}
#endif

	ow = promif_preout();
	promif_preprom();

#ifdef PROM_32BIT_ADDRS

	if ((uintptr_t)buf > (uint32_t)-1) {
		/*
		 * If buf is small enough, use smallbuf
		 * instead of promplat_alloc() (see above)
		 * smallbuf is static, so single thread
		 * access to it by using it only after
		 * promif_preprom()
		 */
		if (len <= sizeof (smallbuf)) {
			promplat_bcopy(buf, smallbuf, len);
			buf = smallbuf;
		}
	}
#endif
	/*
	 * If the callback address is set, attempt to redirect
	 * console output back into kernel terminal emulator.
	 */
	if (promif_redirect != NULL &&
	    fd == prom_stdout_ihandle()) {
		/*
		 * even if we're re-directing output to the kernel
		 * console device, we still have to call promif_preout()
		 * and promif_preprom() because these functions make sure
		 * that the console device is powered up before sending
		 * output to it.
		 */
		rlen = promif_redirect(promif_redirect_arg,
		    (uchar_t *)buf, len);
	} else {
		ci[0] = p1275_ptr2cell("write");	/* Service name */
		ci[1] = (cell_t)3;			/* #argument cells */
		ci[2] = (cell_t)1;			/* #result cells */
		ci[3] = p1275_uint2cell((uint_t)fd);	/* Arg1: ihandle */
		ci[4] = p1275_ptr2cell(buf);		/* Arg2: buffer addr */
		ci[5] = p1275_size2cell(len);		/* Arg3: buffer len */
		ci[6] = (cell_t)-1;			/* Res1: Prime result */

		(void) p1275_cif_handler(&ci);
		rlen = p1275_cell2size(ci[6]);		/* Res1: actual len */
	}

	promif_postprom();
	promif_postout(ow);

#ifdef PROM_32BIT_ADDRS
	if (obuf != NULL)
		promplat_free(buf, len);
#endif

	return (rlen);
}

int
prom_close(int fd)
{
	cell_t ci[4];
	promif_owrap_t *ow;

	ci[0] = p1275_ptr2cell("close");	/* Service name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)0;			/* #result cells */
	ci[3] = p1275_uint2cell((uint_t)fd);	/* Arg1: ihandle */

	ow = promif_preout();
	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();
	promif_postout(ow);

	return (0);
}
