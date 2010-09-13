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

/*
 * initialize metadevices
 */

#include <meta.h>
#include <sys/lvm/mdio.h>
#include <libdevinfo.h>


int
parse_interlace(
	char		*uname,		/* Meta Device name (eg d0) */
	char		*str,		/* String to Parse		 */
	diskaddr_t	*interlacep,
	md_error_t	*ep
)
{
	diskaddr_t	num;
	char		c;
	int		cnt;

	/* parse interlace */
	if ((cnt = sscanf(str, "%llu%c", &num, &c)) < 1) {
		return (meta_cook_syntax(ep, MDE_BAD_INTERLACE,
		    uname, 1, &str));
	} else if (cnt == 1) {
		if (num & (DEV_BSIZE - 1)) {
			return (meta_cook_syntax(ep, MDE_BAD_INTERLACE,
			    uname, 1, &str));
		}
		num = lbtodb(num);
	} else switch (c) {
	case 'b':
	case 'B':
		num *= DEV_BSIZE / DEV_BSIZE;
		break;
	case 'k':
	case 'K':
		num *= 1024 / DEV_BSIZE;
		break;
	case 'm':
	case 'M':
		num *= 1024 * 1024 / DEV_BSIZE;
		break;
	default:
		return (meta_cook_syntax(ep, MDE_BAD_INTERLACE,
		    NULL, 1, &str));
	}

	/* return success */
	*interlacep = num;
	return (0);
}

/*
 * cook up syntax error
 */
int
meta_cook_syntax(
	md_error_t	*ep,
	md_void_errno_t	errcode,
	char		*uname,
	int		argc,
	char		*argv[]
)
{
	int		rval;

	/* if we have a token, concat it to uname */
	if ((argc > 0) && (argv[0] != NULL) && (argv[0][0] != '\0')) {
		char	*p;

		if ((uname != NULL) && (uname[0] != '\0')) {
			p = Malloc(strlen(uname) + 2
			    + 1 + strlen(argv[0]) + 1 + 1);
			(void) strcpy(p, uname);
			(void) strcat(p, ": ");
		} else {
			p = Malloc(1 + strlen(argv[0]) + 1 + 1);
			p[0] = '\0';
		}
		(void) strcat(p, "\"");
		(void) strcat(p, argv[0]);
		(void) strcat(p, "\"");
		rval = mderror(ep, errcode, p);
		Free(p);
	} else {
		rval = mderror(ep, errcode, uname);
	}

	return (rval);
}

int
meta_check_devicesize(
	diskaddr_t	total_blocks
)
{
	int	rval = MD_CRO_32BIT;


	if (total_blocks > MD_MAX_BLKS_FOR_SMALL_DEVS) {
		rval = MD_CRO_64BIT;
	}
	return (rval);
}


/*
 * setup metadevice geometry
 */
/*ARGSUSED*/
int
meta_setup_geom(
	md_unit_t	*md,
	mdname_t	*np,
	mdgeom_t	*geomp,
	uint_t		write_reinstruct,
	uint_t		read_reinstruct,
	uint_t		round_cyl,
	md_error_t	*ep
)
{
	diskaddr_t	cylsize = geomp->nhead * geomp->nsect;
	diskaddr_t	total_blocks;

	if (round_cyl) {
		total_blocks = rounddown(md->c.un_actual_tb, cylsize);
	} else {
		total_blocks = md->c.un_actual_tb;
	}

	md->c.un_total_blocks = total_blocks;
	md->c.un_nhead = geomp->nhead;
	md->c.un_nsect = geomp->nsect;
	md->c.un_rpm = geomp->rpm;
	md->c.un_wr_reinstruct = write_reinstruct;
	md->c.un_rd_reinstruct = read_reinstruct;
	return (0);
}

/*
 * adjust metadevice geometry
 */
/*ARGSUSED*/
int
meta_adjust_geom(
	md_unit_t	*md,
	mdname_t	*np,
	uint_t		write_reinstruct,
	uint_t		read_reinstruct,
	uint_t		round_cyl,
	md_error_t	*ep
)
{
	diskaddr_t	cylsize = md->c.un_nhead * md->c.un_nsect;
	diskaddr_t	total_blocks;

	if (round_cyl) {
		total_blocks = rounddown(md->c.un_actual_tb, cylsize);
	} else {
		total_blocks = md->c.un_actual_tb;
	}

	md->c.un_total_blocks = total_blocks;
	if (write_reinstruct > md->c.un_wr_reinstruct)
		md->c.un_wr_reinstruct = write_reinstruct;
	if (read_reinstruct > md->c.un_rd_reinstruct)
		md->c.un_rd_reinstruct = read_reinstruct;
	return (0);
}

/*
 * Function: meta_init_make_device
 * Purpose:
 * 	Create the device node <uname> by constructing the necessary
 * 	md_mkdev_params_t structure. We have to handle relative names
 *	(e.g. "d80") and fully-qualified names (e.g. "/dev/md/red/dsk/d80").
 *	The field that we need is the unit number of the metadevice (80 in
 *	the above examples).
 * Input:	spp	set structure
 *		uname	unit-name (fully qualified or relative)
 * Output:	ep	error return structure
 * Returns:	> 0	success and return 'key'
 *		-1	Error. <ep> contains error reason
 */
mdkey_t
meta_init_make_device(
	mdsetname_t	**spp,
	char		*uname,
	md_error_t	*ep
)
{
	md_mkdev_params_t	params;
	mdkey_t			rval = 0;
	char			*p;
	int			len = strlen(uname);

	(void) memset(&params, 0, sizeof (params));
	MD_SETDRIVERNAME(&params, "md", (*spp)->setno);

	/*
	 * This ioctl call causes kernel to allocate a unit number
	 * and populate /devices for the named metadevice
	 */
	if (metaioctl(MD_IOCMAKE_DEV, &params, &params.mde, NULL) != 0) {
		return (mdstealerror(ep, &params.mde));
	}

	/*
	 * Now we have minor number so add it to the namespace
	 * and return the key
	 */
	if ((rval = add_self_name(*spp, uname, &params, ep)) <= 0) {
		if (mdisok(ep))
			(void) mderror(ep, MDE_UNIT_NOT_FOUND, NULL);

		return (-1);
	}

	/* Make sure the /dev link is created */
	if (meta_update_devtree(MD_MKMIN((*spp)->setno, params.un)) != 0) {
		/*
		 * Delete name entry we just created
		 */
		(void) del_self_name(*spp, rval, ep);
		p = Malloc(len + 3);
		(void) snprintf(p, len + 3, "\"%s\"", uname);
		rval = mderror(ep, MDE_UNIT_NOT_FOUND, p);
		Free(p);
	}
	return (rval);
}

/*
 * FUNCTION:	is_metadb_cmd()
 * INPUT:	argc	- number of command line arguments
 *		argv	- pointer to array of command line arguments
 * OUTPUT:	none
 * RETURNS:	TRUE if a metadb is to be created, FALSE otherwise
 * PURPOSE:	parses enough of the command line to determine if a metadb
 *		create is being attempted
 */
static boolean_t
is_metadb_cmd(
	int	argc,
	char	*argv[]
)
{
	ulong_t	num;
	int	len;

	/* look for match */
	if (argc > 0 && (sscanf(argv[0], "mddb%lu%n", &num, &len) == 1) &&
		    (strlen(argv[0]) == len) && ((long)num >= 0)) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * FUNCTION:	is_stripe_cmd()
 * INPUT:	argc	- number of command line arguments
 *		argv	- pointer to array of command line arguments
 * OUTPUT:	none
 * RETURNS:	TRUE if a stripe is to be created, FALSE otherwise
 * PURPOSE:	parses enough of the command line to determine if a stripe
 *		create is being attempted
 */
static boolean_t
is_stripe_cmd(
	int	argc,
	char	*argv[]
)
{
	uint_t	nrow;

	if (argc > 1 && (sscanf(argv[1], "%u", &nrow) != 1) || ((int)nrow < 0))
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * FUNCTION:	meta_get_init_type()
 * INPUT:	argc	- number of command line arguments
 *		argv	- pointer to array of command line arguments
 * OUTPUT:	none
 * RETURNS:	type of metadevice or hot spare pools being initialized
 * PURPOSE:	parses enough of the command line to determine what type
 *		of metainit is being attempted
 */
mdinittypes_t
meta_get_init_type(
	int 	argc,
	char	*argv[]
)
{
	char		*arg = argv[1];
	mdinittypes_t	init_type;

	if (argc == 1) /* must be a hot spare pool w/o devices */
		return (TAB_HSP);

	init_type = TAB_UNKNOWN;
	if (arg != NULL) {
		if (strcmp(arg, "-m") == 0) {
			init_type = TAB_MIRROR;
		} else if (strcmp(arg, "-r") == 0) {
			init_type = TAB_RAID;
		} else if (strcmp(arg, "-p") == 0) {
			init_type = TAB_SP;
		} else if (strcmp(arg, "-t") == 0) {
			init_type = TAB_TRANS;
		} else if (is_metadb_cmd(argc, argv)) {
			init_type = TAB_MDDB;
		} else if (is_stripe_cmd(argc, argv)) {
			init_type = TAB_STRIPE;
		} else { /* assume that it is a hsp */
			init_type = TAB_HSP;
		}
	}
	return (init_type);
}

/*
 * initialize named device or hotspare pool
 */
int
meta_init_name(
	mdsetname_t	**spp,
	int		argc,
	char		*argv[],
	char		*cname, /* canonical name */
	mdcmdopts_t	options,
	md_error_t	*ep
)
{
	mdinittypes_t	init_type;
	char		*p;
	int		rval;
	char		*uname = argv[0];
	mdkey_t		key = MD_KEYWILD;
	minor_t		mnum;
	md_error_t	t_e = mdnullerror;

	assert(argc > 0);
	assert(*spp != NULL);

	/* determine type of metadevice or hot spare pool being created */
	init_type = meta_get_init_type(argc, argv);

	/*
	 * Metatrans is eof
	 */
	if (init_type == TAB_TRANS)
		return (mderror(ep, MDE_EOF_TRANS, NULL));

	/* hotspare pool */
	if (init_type == TAB_HSP)
		return (meta_init_hsp(spp, argc, argv, options, ep));

	/*
	 * We are creating metadevice so make sure the name
	 * has not been used
	 */
	if (is_existing_meta_hsp(*spp, cname)) {
		/*
		 * The name has been used by hsp
		 */
		if (is_existing_hsp(*spp, cname)) {
			return (mderror(ep, MDE_NAME_IN_USE, cname));
		}

		/*
		 * If path exists but unit is not created
		 * then meta_init_make_device will correct
		 * that.  If unit also exists then it
		 * will return a conflict error
		 */
		if (init_type != TAB_UNKNOWN) {
		    /* Create device node */
		    if ((key = meta_init_make_device(spp, uname,
			&t_e)) <= 0) {
			return (mdstealerror(ep, &t_e));
		    }
		}
	}

	/* metadevice */
	if (argc >= 2 && init_type != TAB_UNKNOWN) {
		/*
		 * We need to create the device node if the specified metadevice
		 * does not already exist in the database. The actual creation
		 * is undertaken by the md driver and the links propagated by
		 * devfsadm.
		 */
		if (key == MD_KEYWILD) {
			if ((key = meta_init_make_device(spp, uname,
			    &t_e)) <= 0)
				return (mdstealerror(ep, &t_e));
		}

		switch (init_type) {
		case TAB_MIRROR:
			rval = meta_init_mirror(spp, argc, argv, options, ep);
			break;
		case TAB_RAID:
			rval = meta_init_raid(spp, argc, argv, options, ep);
			break;
		case TAB_SP:
			rval = meta_init_sp(spp, argc, argv, options, ep);
			break;
		case TAB_STRIPE:
			rval = meta_init_stripe(spp, argc, argv, options, ep);
			break;
		}

		if (rval == -1 || !(options & MDCMD_DOIT)) {
			/*
			 * Remove the device node created before
			 */
			if ((meta_getnmentbykey((*spp)->setno, MD_SIDEWILD,
			    key, NULL, &mnum, NULL, ep) != NULL) &&
			    MD_MIN2UNIT(mnum) < MD_MAXUNITS) {
			    (void) metaioctl(MD_IOCREM_DEV, &mnum, &t_e, NULL);
			}

			/*
			 * Del what we added before
			 */
			(void) del_self_name(*spp, key, &t_e);
		}
		return (rval);
	}

	/* unknown type */
	p = Malloc(1 + strlen(uname) + 1 + 1);
	(void) strcpy(p, "\"");
	(void) strcat(p, uname);
	(void) strcat(p, "\"");
	rval = mderror(ep, MDE_SYNTAX, p);
	Free(p);
	return (rval);
}
