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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Just in case we're not in a build environment, make sure that
 * TEXT_DOMAIN gets set to something.
 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif

/*
 * report metadevice status
 */

#include <meta.h>

/*
 * print named metadevice
 */
int
meta_print_name(
	mdsetname_t	*sp,
	mdname_t	*namep,
	mdnamelist_t   **nlpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	mdnamelist_t	**lognlpp,
	md_error_t	*ep
)
{
	char		*miscname;

	/* must have set */
	assert(sp != NULL);

	/* get type */
	if ((miscname = metagetmiscname(namep, ep)) == NULL)
		return (-1);

	/* dispatch */
	if (strcmp(miscname, MD_TRANS) == 0) {
		return (meta_trans_print(sp, namep, nlpp, fname, fp,
		    options, NULL, lognlpp, ep));
	}
	if (strcmp(miscname, MD_MIRROR) == 0) {
		return (meta_mirror_print(sp, namep, nlpp, fname, fp,
		    options, ep));
	}
	if (strcmp(miscname, MD_RAID) == 0) {
		return (meta_raid_print(sp, namep, nlpp, fname, fp,
		    options, ep));
	}
	if (strcmp(miscname, MD_STRIPE) == 0) {
		return (meta_stripe_print(sp, namep, nlpp, fname, fp,
		    options, ep));
	}
	if (strcmp(miscname, MD_SP) == 0) {
		return (meta_sp_print(sp, namep, nlpp, fname, fp,
		    options, ep));
	}

	/* unknown type */
	return (mdmderror(ep, MDE_UNKNOWN_TYPE, meta_getminor(namep->dev),
	    namep->cname));
}

/*
 * print all metadevices
 */
int
meta_print_all(
	mdsetname_t	*sp,
	char		*fname,
	mdnamelist_t	**nlpp,
	FILE		*fp,
	mdprtopts_t	options,
	int		*meta_print_trans_msgp,
	md_error_t	*ep
)
{
	md_error_t	status = mdnullerror;
	int		rval = 0;
	mdnamelist_t	*lognlp = NULL;


	/* print various types (save first error) */
	if (meta_trans_print(sp, NULL, nlpp, fname, fp, options,
	    meta_print_trans_msgp, &lognlp, ep) != 0) {
		rval = -1;
		ep = &status;
	}
	if (meta_logs_print(sp, lognlp, nlpp, fname, fp, options, ep) != 0) {
		rval = -1;
		ep = &status;
	}
	metafreenamelist(lognlp);
	if (meta_mirror_print(sp, NULL, nlpp, fname, fp, options, ep) != 0) {
		rval = -1;
		ep = &status;
	}
	if (meta_raid_print(sp, NULL, nlpp, fname, fp, options, ep) != 0) {
		rval = -1;
		ep = &status;
	}
	if (meta_stripe_print(sp, NULL, nlpp, fname, fp, options, ep) != 0) {
		rval = -1;
		ep = &status;
	}
	if (meta_sp_print(sp, NULL, nlpp, fname, fp, options, ep) != 0) {
		rval = -1;
		ep = &status;
	}
	if (meta_hsp_print(sp, NULL, nlpp, fname, fp, options, ep) != 0) {
		rval = -1;
		ep = &status;
	}

	/* discard further errors */
	mdclrerror(&status);

	/* return success */
	return (rval);
}

/*
 * format timestamp
 */
char *
meta_print_time(
	md_timeval32_t	*tvp
)
{
	static char	buf[128];
	struct tm	*tmp;
	char		*dcmsg;

	if (tvp == NULL)
		return ("");

	/*
	 * TRANSLATION_NOTE_LC_TIME
	 * This message is the format of file
	 * timestamps written with the -C and
	 * -c options.
	 * %a -- locale's abbreviated weekday name
	 * %b -- locale's abbreviated month name
	 * %e -- day of month [1,31]
	 * %T -- Time as %H:%M:%S
	 * %Y -- Year, including the century
	 */
	dcmsg = dcgettext(TEXT_DOMAIN, "%a %b %e %T %Y", LC_TIME);

	if (((tvp->tv_sec == 0) && (tvp->tv_usec == 0)) ||
	    ((tmp = localtime((const time_t *)&tvp->tv_sec)) == NULL) ||
	    (strftime(buf, sizeof (buf), dcmsg, tmp) == 0)) {
		return (dgettext(TEXT_DOMAIN, "(invalid time)"));
	}
	return (buf);
}

/*
 * format high resolution time into a tuple of seconds:milliseconds:microseconds
 */
char *
meta_print_hrtime(
	hrtime_t	secs
)
{
	long long	sec, msec, usec;
	static char	buf[128];

	usec = secs / 1000;
	msec = usec / 1000;
	sec  = msec / 1000;
	msec %= 1000;
	usec %= 1000;

	(void) snprintf(buf, sizeof (buf), "%4lld:%03lld:%03lld", sec, msec,
	    usec);
	return (buf);
}

/*
 * Routine to print 32 bit bitmasks
 *
 * Takes:
 *	fp	- a file descriptor
 *	fmt	- optional text
 *	ul	- unsigned long bit vector
 *	bitfmt	- special string to map bits to words.
 *		bitfmt is layed out as follows:
 *			byte 0 is the output base.
 *			byte 1 a bit position less than 32
 *			byte 2-n text for position in byte 1
 *			byte n+1 another bit position
 *			byte n+2-m text for position in byte n+1
 *				.
 *				.
 *				.
 *
 *		Eg. - "\020\001DOG\002CAT\003PIG"
 *		Print the bitmask in hex.
 *		If bit 1 (0x0001) is set print "<DOG>"
 *		If bit 2 (0x0002) is set print "<CAT>"
 *		If bit 3 (0x0004) is set print "<PIG>"
 *		If bit 4 (0x0008) is set nothing is printed.
 *		If bit 1 and bit 2 (0x0003) are set print <DOG,CAT>
 *
 *	Returns 0 on OK
 *		EOF on error
 *
 *	Outputs on fp
 *
 */

int
meta_prbits(FILE *fp, const char *fmt, ...)
{
	va_list		ap;
	unsigned long	ul;
	int		set;
	int		n;
	char		*p;

	va_start(ap, fmt);

	if (fmt && *fmt)
		if (fprintf(fp, fmt) == EOF)
			return (EOF);

	ul = va_arg(ap, int);
	p = va_arg(ap, char *);

	switch (*p++) {
	    case 8:
		if (fprintf(fp, "0%lo", ul) == EOF)
			return (EOF);
		break;

	    case 16:
		if (fprintf(fp, "0x%lx", ul) == EOF)
			return (EOF);
		break;

	    default:
	    case 10:
		if (fprintf(fp, "%ld", ul) == EOF)
			return (EOF);
		break;
	}

	if (! ul)
		return (0);

	for (set = 0; (n = *p++) != '\0'; /* void */) {
		if (ul & (1 << (n - 1))) {
			if (fputc(set ? ',' : '<', fp) == EOF)
				return (EOF);
			for (/* void */; (n = *p) > ' '; ++p)
				if (fputc(n, fp) == EOF)
					return (EOF);
			set = 1;
		} else
			for (/* void */; *p > ' '; ++p);
	}
	if (set)
		if (fputc('>', fp) == EOF)
			return (EOF);

	return (0);
}


/*
 * Convert a number of blocks to a string representation
 * Input:  64 bit wide number of blocks
 * Outout: string like "199MB" or "27TB" or "3.5GB"
 * Returns a pointer to the buffer.
 */
char *
meta_number_to_string(diskaddr_t number, u_longlong_t blk_sz)
{
	diskaddr_t save = 0;
	char *M = " KMGTPE"; /* kilo, mega, giga, tera, peta, exa */
	char *uom = M;    /* unit of measurement, initially ' ' (=M[0]) */
	static char buf[64];
	u_longlong_t	total_bytes;

	/* convert from blocks to bytes */
	total_bytes = number * blk_sz;

	/*
	 * Stop scaling when we reached exa bytes, then something is
	 * probably wrong with our number.
	 */
	while ((total_bytes >= 1024) && (*uom != 'E')) {
		uom++; /* next unit of measurement */
		save = total_bytes;
		total_bytes = total_bytes / 1024;
	}

	/* check if we should output a decimal place after the point */
	if (save && ((save / 1024) < 10)) {
		/* sprintf() will round for us */
		float fnum = (float)save / 1024;
		(void) sprintf(buf, "%1.1f %cB", fnum, *uom);
	} else {
		(void) sprintf(buf, "%llu %cB", total_bytes, *uom);
	}
	return (buf);
}

/*
 * meta_get_tstate: get the transient state bits from the kernel.
 * this is for use with printing out the state field in metastat.
 * INPUT: dev64 -- devt of the metadevice
 *	  tstatep -- return for tstate
 *	  ep	-- error
 * RETURN: -1 for error
 *	    0 for success
 */
int
meta_get_tstate(md_dev64_t dev64, uint_t *tstatep, md_error_t *ep)
{
	md_i_get_tstate_t	params;
	minor_t			mnum = meta_getminor(dev64);

	(void) memset(&params, 0, sizeof (params));
	params.id = mnum;
	if (metaioctl(MD_IOCGET_TSTATE, &params, &params.mde, NULL) != 0) {
		return (mdstealerror(ep, &params.mde));
	}
	*tstatep = params.tstate;
	return (0);
}

/*
 * meta_print_devid: print out the devid information, given a mddevid_t list.
 * INPUT: mdsetname_t	set we're looking at
 *	  FILE	where to print to
 *        mddevid_t list to print from.
 *	  md_error_t	error
 * RETURN: -1 for error
 *          0 for success
 */
int
meta_print_devid(
	mdsetname_t	*sp,
	FILE		*fp,
	mddevid_t	*mddevidp,
	md_error_t	*ep
)
{
	int		len = 0;
	mddevid_t	*tmp_mddevidp = NULL;
	ddi_devid_t	did = NULL;
	char		*devid = "";
	int		freedevid = 0;
	char		*reloc = "";


	/* print header */
	if (fprintf(fp, gettext("Device Relocation Information:\n")) < 0)
		return (-1);

	/*
	 * Building a format string on the fly that will
	 * be used in (f)printf. This allows the length
	 * of the ctd to vary from small to large without
	 * looking horrible.
	 */

	tmp_mddevidp = mddevidp;
	while (tmp_mddevidp != NULL) {
		len = max(len, strlen(tmp_mddevidp->ctdname));
		tmp_mddevidp = tmp_mddevidp->next;
	}

	if (fprintf(fp, "%-*s %-5s\t%s\n", len + 2,
	    gettext("Device  "),
	    gettext("Reloc"),
	    gettext("Device ID")) < 0)
		return (-1);

	/* print ctd's and devids */
	while (mddevidp != NULL) {
		did = (ddi_devid_t)
		    meta_getdidbykey(sp->setno, getmyside(sp, ep),
		    mddevidp->key, ep);

		if (did == (ddi_devid_t)NULL) {
			devid = "-";
			reloc = gettext("No ");
			freedevid = 0;
		} else {
			devid = devid_str_encode(did, NULL);
			reloc = gettext("Yes");
			freedevid = 1;
			Free(did);
		}

		if (fprintf(fp, "%-*s %-5s\t%s\n", len + 2, mddevidp->ctdname,
		    reloc, devid) < 0)
			return (-1);

		mddevidp = mddevidp->next;

		if (freedevid == 1)
			devid_str_free(devid);
	}
	return (0);
}
