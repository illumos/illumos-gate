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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <meta.h>
#include <sys/lvm/md_mddb.h>
#include <sdssc.h>

/*
 * print metadevice status
 */


#define	MD_PROBE_OPEN_T "probe open test"

/* used to keep track of the softparts on the same underlying device */
struct sp_base_list {
	struct sp_base_list	*next;
	char			*base;
};

/*
 * Function prototypes
 */
static void probe_all_devs(mdsetname_t *sp);

static int print_devid(mdsetname_t *sp, mdnamelist_t *nlp, FILE *fp,
    md_error_t   *ep);

static md_common_t	*get_concise_unit(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
static void	print_all_sets(mdprtopts_t options, int concise_flag,
		    int quiet_flg);
static void	print_specific_set(mdsetname_t *sp, mdprtopts_t options,
		    int concise_flag, int quiet_flg);
static void	print_concise_diskset(mdsetname_t *sp);
static void	print_concise_namelist(mdsetname_t *sp, mdnamelist_t **nl,
		    char mtype);
static void	print_concise_md(int indent, mdsetname_t *sp, mdname_t *np);
static void	print_concise_mirror(int indent, mdsetname_t *sp,
		    md_mirror_t *mirror);
static void	print_concise_raid(int indent, mdsetname_t *sp,
		    md_raid_t *raid);
static void	print_concise_stripe(int indent, mdsetname_t *sp,
		    md_stripe_t *stripe);
static void	print_concise_sp(int indent, mdsetname_t *sp, md_sp_t *part);
static void	print_concise_trans(int indent, mdsetname_t *sp,
		    md_trans_t *trans);
static void	free_names(mdnamelist_t **nlp);
static char	*get_sm_state(md_mirror_t *mirror, int i,
		    md_status_t mirror_status, uint_t tstate);
static char	*get_raid_col_state(md_raidcol_t *colp, uint_t tstate);
static char	*get_stripe_state(md_comp_t *mdcp, uint_t tstate);
static char	*get_hs_state(md_hs_t *hsp);
static struct sp_base_list *sp_add_done(md_sp_t *part, struct sp_base_list *lp);
static int	sp_done(md_sp_t *part, struct sp_base_list *lp);
static int	sp_match(md_sp_t *part, struct sp_base_list *lp);
static void	sp_free_list(struct sp_base_list *lp);


/*
 * print named hotspare pool or metadevice
 */
static int
print_name(
	mdsetname_t	**spp,
	char		*uname,
	mdnamelist_t	**nlistpp,
	char		*fname,
	FILE		*fp,
	mdprtopts_t	options,
	int		*meta_print_trans_msgp,
	mdnamelist_t	**lognlpp,
	md_error_t	*ep
)
{
	mdname_t	*namep;
	char		*miscname;

	/* recurse */
	options |= PRINT_SUBDEVS;

	/* hotspare pool */
	if (is_existing_hsp(*spp, uname)) {
		mdhspname_t	*hspnamep;

		/* get hotsparepool */
		if ((hspnamep = metahspname(spp, uname, ep)) == NULL)
			return (-1);

		/* check for ownership */
		assert(*spp != NULL);
		if (meta_check_ownership(*spp, ep) != 0)
			return (-1);

		/* print hotspare pool */
		return (meta_hsp_print(*spp, hspnamep, lognlpp, fname, fp,
		    options, ep));
	}

	/* get metadevice */
	if (((namep = metaname(spp, uname, META_DEVICE, ep)) == NULL) ||
	    (metachkmeta(namep, ep) != 0))
		return (-1);

	/* check for ownership */
	assert(*spp != NULL);
	if (meta_check_ownership(*spp, ep) != 0)
		return (-1);

	if ((miscname = metagetmiscname(namep, ep)) != NULL) {
		if (strcmp(miscname, MD_TRANS) == 0) {
			*meta_print_trans_msgp = 1;
		}
	}

	/* print metadevice */
	return (meta_print_name(*spp, namep, nlistpp, fname, fp, options,
	    lognlpp, ep));
}

/*
 * print the per set flags
 */
/*ARGSUSED*/
static int
print_setstat(
	mdsetname_t		**spp,
	char			*fname,
	FILE			*fp,
	mdprtopts_t		options,
	md_error_t		*ep
)
{
	int			rval = -1;
	char			*cname = NULL;
	char			*cp = NULL;
	md_gs_stat_parm_t	gsp;


	if (fname != NULL && strchr(fname, '/') != NULL) {
		/* get the canonical name */
		cname = meta_name_getname(spp, fname, META_DEVICE, ep);
		if (cname == NULL)
			return (-1);
		Free(cname);
	}

	if ((cp = getenv("MD_DEBUG")) == NULL)
		return (0);

	if (strstr(cp, "SETINFO") == NULL)
		return (0);

	(void) memset(&gsp, '\0', sizeof (md_gs_stat_parm_t));
	gsp.gs_setno = (*spp)->setno;

	if (metaioctl(MD_GET_SETSTAT, &gsp, &gsp.gs_mde, NULL) != 0)
		return (mdstealerror(ep, &gsp.gs_mde));

	if (fprintf(fp, "Status for set %d = ", gsp.gs_setno) == EOF)
		goto out;

	if (meta_prbits(fp, NULL, gsp.gs_status, MD_SET_STAT_BITS) == EOF)
		goto out;


	if (fprintf(fp, "\n") == EOF)
		goto out;

	/* success */
	rval = 0;

	/* cleanup, return error */
out:
	if (rval != 0)
		(void) mdsyserror(ep, errno, fname);

	return (rval);
}

/*
 * check_replica_state:
 * 	If the replica state is stale or the set has been halted
 * 	this routine returns an error.
 */
static int
check_replica_state(mdsetname_t *sp, md_error_t *ep)
{
	mddb_config_t	c;

	(void) memset(&c, 0, sizeof (c));
	c.c_id = 0;
	c.c_setno = sp->setno;

	if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0) {
		if (mdismddberror(&c.c_mde, MDE_DB_INVALID))
			mdstealerror(ep, &c.c_mde);
		return (-1);
	}

	if (c.c_flags & MDDB_C_STALE) {
		return (mdmddberror(ep, MDE_DB_STALE, NODEV32, sp->setno,
		    0, NULL));
	} else
		return (0);
}

static void
print_trans_msg(mdprtopts_t	options, int	meta_print_trans_msg)
{
	if (meta_print_trans_msg != 0) {
		fprintf(stderr, "\n\n");
		if (options & PRINT_SHORT) {
			fprintf(stderr, gettext(MD_SHORT_EOF_TRANS_MSG));
			fprintf(stderr, gettext(MD_SHORT_EOF_TRANS_WARNING));
		} else {
			fprintf(stderr, gettext(MD_EOF_TRANS_MSG));
			fprintf(stderr, gettext(MD_EOF_TRANS_WARNING));
		}
	}
}

/*
 * print usage message
 *
 */
static void
usage(
	mdsetname_t	*sp,
	int		eval
)
{
	(void) fprintf(stderr, gettext("\
usage:	%s [-s setname] [-a][-c][-B][-D][-r][-i][-p] [-t] [metadevice...]\n"),
	    myname);
	md_exit(sp, eval);
}

/*
 * mainline. crack command line arguments.
 */
int
main(
	int	argc,
	char	*argv[]
)
{
	char		*sname = MD_LOCAL_NAME;
	mdsetname_t	*sp = NULL;
	mdprtopts_t	options = PRINT_HEADER | PRINT_DEVID | PRINT_FAST;
	int		c;
	char		*p;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	int		eval = 0;
	int		inquire = 0;
	int		quiet_flg = 0;
	int		set_flg = 0;
	int		error;
	int		all_sets_flag = 0;
	int		concise_flag = 0;
	mdnamelist_t	*nlistp = NULL;
	mdname_t		*namep;
	int		devcnt = 0;
	mdnamelist_t	*lognlp = NULL;
	uint_t hsi;
	int		meta_print_trans_msg = 0;

	/*
	 * Get the locale set up before calling any other routines
	 * with messages to ouput.  Just in case we're not in a build
	 * environment, make sure that TEXT_DOMAIN gets set to
	 * something.
	 */
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if (sdssc_bind_library() == SDSSC_OKAY)
		if (sdssc_cmd_proxy(argc, argv, SDSSC_PROXY_PRIMARY,
		    &error) == SDSSC_PROXY_DONE)
			exit(error);

	/* initialize */
	if (md_init(argc, argv, 0, 1, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* parse arguments */
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "acSs:hpBDrtiq?")) != -1) {
		switch (c) {
		case 'a':
			all_sets_flag++;
			break;

		case 'c':
			concise_flag++;
			quiet_flg++;
			break;

		case 'S':
			options |= PRINT_SETSTAT_ONLY;
			break;

		case 's':
			sname = optarg;
			set_flg++;
			break;

		case 'h':
			usage(sp, 0);
			break;

		case 'p':
			options |= PRINT_SHORT;
			options &= ~PRINT_DEVID;
			break;

		case 't':
			options |= PRINT_TIMES;
			break;

		case 'i':
			inquire++;
			break;

		case 'B':
			options |= PRINT_LARGEDEVICES;
			break;
		case 'D':
			options |= PRINT_FN;
			break;
		case 'r':		/* defunct option */
			break;
		case 'q':
			quiet_flg++;
			break;
		case '?':
			if (optopt == '?')
				usage(sp, 0);
			/*FALLTHROUGH*/
		default:
			usage(sp, 1);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (all_sets_flag && set_flg) {
		fprintf(stderr, gettext("metastat: "
		    "incompatible options: -a and -s\n"));
		usage(sp, 1);
	}

	/* get set context */
	if ((sp = metasetname(sname, ep)) == NULL) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* make sure that the mddb is not stale. Else print a warning */

	if (check_replica_state(sp, ep)) {
		if (mdismddberror(ep, MDE_DB_STALE)) {
			fprintf(stdout, gettext(
			    "****\nWARNING: Stale "
			    "state database replicas. Metastat output "
			    "may be inaccurate.\n****\n\n"));
		}
	}

	/* if inquire is set. We probe first */
	if (inquire) {
		if (geteuid() != 0) {
			fprintf(stderr, gettext("metastat: -i "
			    "option requires super-user privilages\n"));
			md_exit(sp, 1);
		}
		probe_all_devs(sp);
	}
	/* print debug stuff */
	if (((p = getenv("MD_DEBUG")) != NULL) &&
	    (strstr(p, "STAT") != NULL)) {
		options |= (PRINT_SETSTAT | PRINT_DEBUG | PRINT_TIMES);
	}

	if ((options & PRINT_SETSTAT) || (options & PRINT_SETSTAT_ONLY)) {
		if (print_setstat(&sp, argv[0], stdout, options, ep)) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}
		if (options & PRINT_SETSTAT_ONLY)
			md_exit(sp, 0);
	}

	/* status all devices */
	if (argc == 0) {
		if (all_sets_flag) {
			print_all_sets(options, concise_flag, quiet_flg);
		} else {
			print_specific_set(sp, options, concise_flag,
			    quiet_flg);
		}

		if (meta_smf_isonline(meta_smf_getmask(), ep) == 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}

		/* success */
		md_exit(sp, 0);
	}
	/* print named device types */
	while (devcnt < argc) {
		char	*uname = argv[devcnt];
		char	*cname = NULL;

		/* get the canonical name */
		cname = meta_name_getname(&sp, uname, META_DEVICE, ep);
		if (cname == NULL) {
			/* already printed the error */
			mdclrerror(ep);
			eval = 1;
			++devcnt;
			continue;
		}

		if (concise_flag) {
			mdname_t *np;

			np = metaname(&sp, cname, META_DEVICE, ep);
			if (np == NULL) {
				mde_perror(ep, "");
				mdclrerror(ep);
				eval = 1;
			} else {
				print_concise_md(0, sp, np);
			}

		} else {
			if (print_name(&sp, cname, &nlistp, NULL, stdout,
			    options, &meta_print_trans_msg, &lognlp, ep) != 0) {
				mde_perror(ep, "");
				mdclrerror(ep);
				eval = 1;
			}
		}
		Free(cname);
		++devcnt;
	}

	/* print metadevice & relocation device id */
	if ((options & PRINT_DEVID) && (eval != 1) && !quiet_flg) {
		devcnt = 0;

		while (devcnt < argc) {
			char	*uname = argv[devcnt];
			char	*cname = NULL;

			/* get the canonical name */
			cname = meta_name_getname(&sp, uname, META_DEVICE, ep);
			if (cname == NULL) {
				mde_perror(ep, "");
				mdclrerror(ep);
				++devcnt;
				continue;
			}

			/* hotspare pools */
			if (is_existing_hsp(sp, cname)) {
				mdhspname_t	*hspnamep;
				md_hsp_t	*hsp;

				/* get hotsparepool */
				if ((hspnamep = metahspname(&sp, cname,
				    ep)) == NULL)
					eval = 1;

				if ((hsp = meta_get_hsp(sp, hspnamep,
				    ep)) == NULL)
					eval = 1;

				for (hsi = 0;
				    hsi < hsp->hotspares.hotspares_len;
				    hsi++) {

					namep = hsp->hotspares.
					    hotspares_val[hsi].hsnamep;

					if (!(options &
					    (PRINT_LARGEDEVICES | PRINT_FN))) {
						/* meta_getdevs populates the */
						/* nlistp structure for use   */
						if (meta_getdevs(sp, namep,
						    &nlistp, ep) != 0)
							eval =  1;
					}

				}

			} else {

				/* get metadevice */
				if (((namep = metaname(&sp, cname,
				    META_DEVICE, ep)) == NULL) ||
				    (metachkmeta(namep, ep) != 0))
					eval = 1;

				if (!(options &
				    (PRINT_LARGEDEVICES | PRINT_FN))) {
					/* meta_getdevs populates the	*/
					/* nlistp structure for use 	*/
					if (meta_getdevs(sp, namep, &nlistp, ep)
					    != 0)
						eval =  1;
				}
			}
			Free(cname);
			++devcnt;
		}
		if (print_devid(sp, nlistp, stdout, ep) != 0)
			eval =  1;


	}

	print_trans_msg(options, meta_print_trans_msg);

	if (meta_smf_isonline(meta_smf_getmask(), ep) == 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	/* return success */
	md_exit(sp, eval);
	/*NOTREACHED*/
	return (eval);
}

static void
print_all_sets(mdprtopts_t options, int concise_flag, int quiet_flg)
{
	uint_t		max_sets;
	md_error_t	error = mdnullerror;
	int		i;

	if ((max_sets = get_max_sets(&error)) == 0) {
		return;
	}

	if (!mdisok(&error)) {
		mdclrerror(&error);
		return;
	}

	/* for each possible set number, see if we really have a diskset */
	for (i = 0; i < max_sets; i++) {
		mdsetname_t		*sp;

		if ((sp = metasetnosetname(i, &error)) == NULL) {
			if (!mdisok(&error) &&
			    mdisrpcerror(&error, RPC_PROGNOTREGISTERED)) {
			/* metad rpc program not registered - no metasets */
				break;
			}

			mdclrerror(&error);
			continue;
		}
		mdclrerror(&error);

		if (meta_check_ownership(sp, &error) == 0) {
			/* we own the set, so we can print the metadevices */
			print_specific_set(sp, options, concise_flag,
			    quiet_flg);
			(void) printf("\n");
		}

		metaflushsetname(sp);
	}
}

static void
print_specific_set(mdsetname_t *sp, mdprtopts_t options, int concise_flag,
	int quiet_flg)
{
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	int		meta_print_trans_msg = 0;

	/* check for ownership */
	assert(sp != NULL);
	if (meta_check_ownership(sp, ep) != 0) {
		mde_perror(ep, "");
		md_exit(sp, 1);
	}

	if (concise_flag) {
		print_concise_diskset(sp);

	} else {
		mdnamelist_t	*nlistp = NULL;

		/* status devices */
		if (meta_print_all(sp, NULL, &nlistp, stdout, options,
		    &meta_print_trans_msg, ep) != 0) {
			mde_perror(ep, "");
			md_exit(sp, 1);
		}

		/* print relocation device id on all dev's */
		if ((options & PRINT_DEVID) && !quiet_flg) {
			/*
			 * Ignore return value from meta_getalldevs since
			 * it will return a failure if even one device cannot
			 * be found - which could occur in the case of device
			 * failure or a device being powered off during
			 * upgrade.  Even if meta_getalldevs fails, the
			 * data in nlistp is still valid.
			 */
			if (!(options & (PRINT_LARGEDEVICES | PRINT_FN))) {
				(void) meta_getalldevs(sp, &nlistp, 0, ep);
			}
			if (nlistp != NULL) {
				if (print_devid(sp, nlistp, stdout, ep) != 0) {
					mde_perror(ep, "");
					md_exit(sp, 1);
				}
			}
		}
	}

	print_trans_msg(options, meta_print_trans_msg);
}

/*
 * print_devid prints out cxtxdx and devid for devices passed in a
 * mdnamelist_t structure
 */
static int
print_devid(
	mdsetname_t  *sp,
	mdnamelist_t *nlp,
	FILE		 *fp,
	md_error_t   *ep
)
{
	int 			retval = 0;
	mdnamelist_t		*onlp = NULL;
	mddevid_t 		*ldevidp = NULL;
	mddevid_t		*nextp;

	/* make a non-duplicate list of nlp */
	for (onlp = nlp; (onlp != NULL); onlp = onlp->next) {
		meta_create_non_dup_list(onlp->namep, &ldevidp);
	}

	retval = meta_print_devid(sp, fp, ldevidp, ep);

	/* cleanup */
	for (nextp = ldevidp; nextp != NULL; ldevidp = nextp) {
		Free(ldevidp->ctdname);
		nextp = ldevidp->next;
		Free(ldevidp);
	}

	return (retval);
}

/*
 * probedev issues ioctls for all the metadevices
 */




/*
 * Failure return's a 1
 */
int
hotspare_ok(char *bname)
{
	int fd;
	char buf[512];

	if ((fd = open(bname, O_RDONLY)) < 0)
		return (0);
	if (read(fd, buf, sizeof (buf)) < 0) {
		(void) close(fd);
		return (0);
	}
	(void) close(fd);
	return (1);
}

void
delete_hotspares_impl(mdsetname_t *sp, mdhspname_t *hspnp, md_hsp_t *hspp)
{
	md_hs_t *hsp;
	uint_t		hsi;
	char    *bname;
	md_error_t e = mdnullerror;
	int deleted_hs = 0;

	for (hsi = 0; (hsi < hspp->hotspares.hotspares_len); ++hsi) {
		mdnamelist_t *nlp;

		hsp = &hspp->hotspares.hotspares_val[hsi];
		bname = hsp->hsnamep->bname;
		nlp = NULL;
		metanamelist_append(&nlp, hsp->hsnamep);
		/* print hotspare */
		if (hsp->state == HSS_AVAILABLE) {
			if (hotspare_ok(bname))
				continue;

			fprintf(stderr,
			    "NOTICE: Hotspare %s in %s has failed.\n"
			    "\tDeleting %s since it not in use\n\n",
			    bname, hspnp->hspname, bname);

			if (meta_hs_delete(sp, hspnp, nlp, 0, &e) != NULL) {
				mde_perror(&e, "");
			} else {
				deleted_hs++;
			}
		}
	}
}



/*
 * Generic routine to issue ioctls
 */

void
md_setprobetest(md_probedev_t *iocp)
{
	(void) strcpy(iocp->test_name, MD_PROBE_OPEN_T);
}

int
md_probe_ioctl(mdsetname_t *sp, mdnamelist_t *nlp, int ndevs, char *drvname)
{
	mdnamelist_t	*p;
	mdname_t	*np;
	md_probedev_t	probe_ioc, *iocp;
	int		i, retval = 0;
	/*
	 * Allocate space for all the metadevices and fill in
	 * the minor numbers.
	 */

	memset(&probe_ioc, 0, sizeof (probe_ioc));
	iocp = &probe_ioc;

	if ((iocp->mnum_list = (uintptr_t)calloc(ndevs, sizeof (minor_t)))
	    == 0) {
		perror("md_probe_ioctl: calloc");
		return (-1);
	}

	MD_SETDRIVERNAME(iocp, drvname, sp->setno);
	md_setprobetest(iocp);

	iocp->nmdevs = ndevs;

	for (p = nlp, i = 0; p; p = p->next, i++) {
		np = p->namep;
		((minor_t *)(uintptr_t)iocp->mnum_list)[i] =
		    meta_getminor(np->dev);
	}


	if (metaioctl(MD_IOCPROBE_DEV, iocp, &(iocp->mde), NULL) != 0)
			retval = -1;
	return (retval);
}
/*
 *
 *  - remove p from nlp list
 *  - put it on the toplp list.
 *  - update the p to the next element
 */

void
add_to_list(mdnamelist_t **curpp, mdnamelist_t **prevpp, mdnamelist_t **newlpp)
{
	mdnamelist_t	*p, *prevp, *nlp;

	p = *curpp;
	prevp = *prevpp;
	nlp = *newlpp;

	if (prevp == p) {
		/* if first element reset prevp */
			prevp = p->next;
			p->next = nlp;
			nlp = p;
			p = prevp;
	} else {
		prevp->next = p->next;
		p->next = nlp;
		nlp = p;
		p = prevp->next;
	}
	*curpp = p;
	*prevpp = prevp;
	*newlpp = nlp;
}
/*
 * Scans the given list of metadeivces and returns a list of top level
 * metadevices.
 * Note: The orignal list is not valid at the end and is set to NULL.
 */

int
get_toplevel_mds(mdsetname_t *sp, mdnamelist_t **lpp,
			mdnamelist_t **top_pp)
{
	mdnamelist_t	*p, *prevp, *toplp;
	int		ntopmd;
	md_common_t	*mdp;
	md_error_t	e = mdnullerror;

	ntopmd = 0;
	prevp = p = *lpp;
	toplp = NULL;

	while (p) {
		if ((mdp = meta_get_unit(sp, p->namep, &e)) == NULL) {
				prevp = p;
				p = p->next;
				continue;
		}

		if (mdp->parent == MD_NO_PARENT) {
			/* increment the top level md count. */
			ntopmd++;
			add_to_list(&p, &prevp, &toplp);
		} else {
			prevp = p;
			p = p->next;
		}
	}
	*lpp = NULL;
	*top_pp = toplp;

	return (ntopmd);
}

int
get_namelist(mdnamelist_t **transdevlist, mdnamelist_t **devlist,
					char *dev_type)
{
	mdnamelist_t *np, *prevp;
	md_error_t	e = mdnullerror;
	char		*type_name;
	int		i = 0;

	prevp = np = *transdevlist;
	while (np) {
		if ((type_name = metagetmiscname(np->namep, &e)) == NULL) {
			*devlist = NULL;
			return (-1);
		}
		if (strcmp(type_name, dev_type) == 0) {
			/* move it to the devlist */
			add_to_list(&np, &prevp, devlist);
			i++;
		} else {
			prevp = np;
			np = np->next;
		}
	}
	return (i);
}


mdnamelist_t *
create_nlp(mdsetname_t *sp)
{
	mdnamelist_t *np;
	md_error_t   e = mdnullerror;

	if (np = (mdnamelist_t *)malloc(sizeof (mdnamelist_t))) {
		np->next = NULL;
		return (np);
	} else {
		/* error condition below */
		mde_perror(&e, "create_nlp: malloc failed\n");
		md_exit(sp, 1);
	}
	return (0);
}

/*
 * Create a list of metadevices associated with trans. top_pp points to
 * this list. The number of components in the list are also returned.
 */
int
create_trans_compslist(mdsetname_t *sp, mdnamelist_t **lpp,
				mdnamelist_t **top_pp)
{
	mdnamelist_t	*p, *tailp, *toplp, *newlp;
	int		ntoptrans;
	md_error_t	e = mdnullerror;
	md_trans_t	*tp;

	ntoptrans = 0;
	p = *lpp;
	tailp = toplp = NULL;
	/*
	 * Scan the current list of trans devices. From that
	 * extract all the lower level metadevices and put them on
	 * toplp list.
	 */

	while (p) {
		if (tp = meta_get_trans(sp, p->namep, &e)) {
			/*
			 * Check the master and log devices to see if they
			 * are metadevices
			 */
			if (metaismeta(tp->masternamep)) {
				/* get a mdnamelist_t. */
				newlp = create_nlp(sp);
				newlp->namep = tp->masternamep;
				if (toplp == NULL) {
					toplp = tailp = newlp;
				} else {
					tailp->next = newlp;
					tailp = newlp;
				}
				ntoptrans++;
			}

			if (tp->lognamep && metaismeta(tp->lognamep)) {
				newlp = create_nlp(sp);
				newlp->namep = tp->lognamep;
				if (toplp == NULL) {
					toplp = tailp = newlp;
				} else {
					tailp->next = newlp;
					tailp = newlp;
				}
				ntoptrans++;
			}
			p = p->next;
		}
	}
	*top_pp = toplp;
	return (ntoptrans);
}

void
probe_mirror_devs(mdsetname_t *sp)
{
	mdnamelist_t	*nlp, *toplp;
	int		cnt;
	md_error_t	e = mdnullerror;

	nlp = toplp = NULL;

	if (meta_get_mirror_names(sp, &nlp, 0, &e) > 0) {
		/*
		 * We have some mirrors to probe
		 * get a list of top-level mirrors
		 */

		cnt = get_toplevel_mds(sp, &nlp, &toplp);
		if (cnt && (md_probe_ioctl(sp, toplp, cnt, MD_MIRROR) < 0))
				perror("MD_IOCPROBE_DEV");
	}
	metafreenamelist(nlp);
	metafreenamelist(toplp);

}

void
probe_raid_devs(mdsetname_t *sp)
{
	mdnamelist_t	*nlp, *toplp;
	int		cnt;
	md_error_t	e = mdnullerror;

	nlp = toplp = NULL;

	if (meta_get_raid_names(sp, &nlp, 0, &e) > 0) {
		/*
		 * We have some mirrors to probe
		 * get a list of top-level mirrors
		 */

		cnt = get_toplevel_mds(sp, &nlp, &toplp);

		if (cnt && (md_probe_ioctl(sp, toplp, cnt, MD_RAID) < 0))
			perror("MD_IOCPROBE_DEV");
	}
	metafreenamelist(nlp);
	metafreenamelist(toplp);
}

/*
 * Trans probes are diffenent. -- so whats new.
 * we separate out the master and log device and then issue the
 * probe calls.
 * Since the underlying device could be disk, stripe, RAID or miror,
 * we have to sort them out and then call the ioctl for each.
 */

void
probe_trans_devs(mdsetname_t *sp)
{
	mdnamelist_t	*nlp, *toplp;
	mdnamelist_t	*trans_raidlp, *trans_mmlp, *trans_stripelp;
	int		cnt;
	md_error_t	e = mdnullerror;

	nlp = toplp = NULL;
	trans_raidlp = trans_mmlp = trans_stripelp = NULL;

	if (meta_get_trans_names(sp, &nlp, 0, &e) > 0) {
		/*
		 * get a list of master and log metadevices.
		 */

		cnt = create_trans_compslist(sp, &nlp, &toplp);

		/* underlying RAID-5 components */

		cnt = get_namelist(&toplp, &trans_raidlp, MD_RAID);
		if ((cnt > 0) && (md_probe_ioctl(sp, trans_raidlp, cnt,
		    MD_RAID) < 0))
			perror("MD_IOCPROBE_DEV");

		metafreenamelist(trans_raidlp);

		/* underlying mirror components */

		cnt = get_namelist(&toplp, &trans_mmlp, MD_MIRROR);

		if ((cnt > 0) && (md_probe_ioctl(sp, trans_mmlp, cnt,
		    MD_MIRROR) < 0))
			perror("MD_IOCPROBE_DEV");

		metafreenamelist(trans_mmlp);

		/* underlying stripe components */

		cnt = get_namelist(&toplp, &trans_stripelp, MD_STRIPE);
		if ((cnt > 0) && (md_probe_ioctl(sp, trans_stripelp, cnt,
		    MD_STRIPE) < 0))
			perror("MD_IOCPROBE_DEV");
		metafreenamelist(trans_stripelp);
		metafreenamelist(nlp);
	}
}

/*
 * probe hot spares. This is differs from other approaches since
 * there are no read/write routines through md. We check at the physical
 * component level and then delete it if its bad.
 */

void
probe_hotspare_devs(mdsetname_t *sp)
{
	mdhspnamelist_t *hspnlp = NULL;
	int		cnt;
	mdhspnamelist_t	*p;
	md_hsp_t	*hspp;
	md_error_t	e = mdnullerror;

	if ((cnt = meta_get_hsp_names(sp, &hspnlp, 0, &e)) < 0) {
		mderror(&e, MDE_UNIT_NOT_FOUND, NULL);
		return;
	} else if (cnt == 0) {
		mderror(&e, MDE_NO_HSPS, NULL);
		return;
	}
	for (p = hspnlp; (p != NULL); p = p->next) {
		mdhspname_t	*hspnp = p->hspnamep;


		if ((hspp = meta_get_hsp(sp, hspnp, &e)) == NULL)
			continue;

		if (hspp->hotspares.hotspares_len != 0) {
			delete_hotspares_impl(sp, hspnp, hspp);
		}
	}
	metafreehspnamelist(hspnlp);
}

static void
probe_all_devs(mdsetname_t *sp)
{
	probe_hotspare_devs(sp);
	probe_mirror_devs(sp);
	probe_raid_devs(sp);
	probe_trans_devs(sp);
}

/*
 * The following functions are used to print the concise output
 * of the metastat coommand (-c option).
 *
 * Normally the output for metastat is performed within libmeta via
 * the *_report functions within each of the metadevice specific files in
 * libmeta.  However, it is usually bad architecture for a library to
 * perform output since there are so many different ways that an application
 * can choose to do output (e.g. GUI, CLI, CIM, SNMP, etc.).  So, for the
 * concise output option we have moved the CLI output to the metastat
 * code and just use libmeta as the source of data to be printed.
 *
 * This function gets all of the different top-level metadevices in the set
 * and prints them.  It calls the print_concise_md() function to recursively
 * print the metadevices that underly the top-level metadevices.  It does
 * special handling for soft partitions so that all of the SPs on the
 * same underlying device are grouped and then that underlying device
 * is only printed once.
 */
static void
print_concise_diskset(mdsetname_t *sp)
{
	md_error_t		error = mdnullerror;
	mdnamelist_t		*nl = NULL;
	mdhspnamelist_t		*hsp_list = NULL;

	/*
	 * We do extra handling for soft parts since we want to find
	 * all of the SPs on the same underlying device, group them and
	 * print them together before printing the underlying device just
	 * once.  This logic doesn't apply to any other metadevice type.
	 */
	if (meta_get_sp_names(sp, &nl, 0, &error) >= 0) {
		mdnamelist_t	*nlp;
		/* keep track of the softparts on the same underlying device */
		struct sp_base_list	*base_list = NULL;

		for (nlp = nl; nlp != NULL; nlp = nlp->next) {
			mdname_t	*mdn;
			md_sp_t		*soft_part;
			mdnamelist_t	*tnlp;

			mdn = metaname(&sp, nlp->namep->cname,
			    META_DEVICE, &error);
			mdclrerror(&error);
			if (mdn == NULL) {
				print_concise_entry(0, nlp->namep->cname,
				    0, 'p');
				printf("\n");
				continue;
			}

			soft_part = meta_get_sp_common(sp, mdn, 1, &error);
			mdclrerror(&error);

			if (soft_part == NULL ||
			    MD_HAS_PARENT(soft_part->common.parent) ||
			    sp_done(soft_part, base_list))
				continue;

			/* print this soft part */
			print_concise_entry(0, soft_part->common.namep->cname,
			    soft_part->common.size, 'p');
			(void) printf(" %s\n", soft_part->compnamep->cname);

			/*
			 * keep track of the underlying device of
			 * this soft part
			 */
			base_list = sp_add_done(soft_part, base_list);

			/*
			 * now print all of the other soft parts on the same
			 * underlying device
			 */
			for (tnlp = nlp->next; tnlp != NULL; tnlp =
			    tnlp->next) {
				md_sp_t		*part;

				mdn = metaname(&sp, tnlp->namep->cname,
				    META_DEVICE, &error);

				mdclrerror(&error);
				if (mdn == NULL)
					continue;

				part = meta_get_sp_common(sp, mdn, 1, &error);
				mdclrerror(&error);

				if (part == NULL || MD_HAS_PARENT(
				    part->common.parent) ||
				    ! sp_match(part, base_list))
					continue;

				/* on the same base so print this soft part */
				print_concise_entry(0,
				    part->common.namep->cname,
				    part->common.size, 'p');
				(void) printf(" %s\n", part->compnamep->cname);
			}

			/*
			 * print the common metadevice hierarchy
			 * under these soft parts
			 */
			print_concise_md(META_INDENT, sp, soft_part->compnamep);
		}

		free_names(&nl);
		sp_free_list(base_list);
	}
	mdclrerror(&error);

	if (meta_get_trans_names(sp, &nl, 0, &error) >= 0)
		print_concise_namelist(sp, &nl, 't');
	mdclrerror(&error);

	if (meta_get_mirror_names(sp, &nl, 0, &error) >= 0)
		print_concise_namelist(sp, &nl, 'm');
	mdclrerror(&error);

	if (meta_get_raid_names(sp, &nl, 0, &error) >= 0)
		print_concise_namelist(sp, &nl, 'r');
	mdclrerror(&error);

	if (meta_get_stripe_names(sp, &nl, 0, &error) >= 0)
		print_concise_namelist(sp, &nl, 's');
	mdclrerror(&error);

	if (meta_get_hsp_names(sp, &hsp_list, 0, &error) >= 0) {
		mdhspnamelist_t *nlp;

	for (nlp = hsp_list; nlp != NULL; nlp = nlp->next) {
		md_hsp_t	*hsp;

		print_concise_entry(0, nlp->hspnamep->hspname, 0, 'h');

		hsp = meta_get_hsp_common(sp, nlp->hspnamep, 1, &error);
		mdclrerror(&error);
		if (hsp != NULL) {
			int	i;

			for (i = 0; i < hsp->hotspares.hotspares_len; i++) {
				md_hs_t	*hs;
				char	*state;

				hs = &hsp->hotspares.hotspares_val[i];

				(void) printf(" %s", hs->hsnamep->cname);

				state = get_hs_state(hs);
				if (state != NULL)
					(void) printf(" (%s)", state);
			}
		}

		(void) printf("\n");
	}

	metafreehspnamelist(hsp_list);
	}
}

/*
 * Print the top-level metadevices in the name list for concise output.
 */
static void
print_concise_namelist(mdsetname_t *sp, mdnamelist_t **nl, char mtype)
{
	mdnamelist_t	*nlp;
	md_error_t	error = mdnullerror;

	for (nlp = *nl; nlp != NULL; nlp = nlp->next) {
		mdname_t	*mdn;
		md_common_t	*u;

		mdn = metaname(&sp, nlp->namep->cname, META_DEVICE, &error);
		mdclrerror(&error);
		if (mdn == NULL) {
			print_concise_entry(0, nlp->namep->cname, 0, mtype);
			printf("\n");
			continue;
		}

		u = get_concise_unit(sp, mdn, &error);
		mdclrerror(&error);

		if (u != NULL && !MD_HAS_PARENT(u->parent))
			print_concise_md(0, sp, mdn);
	}

	free_names(nl);
}

/*
 * Concise mirror output.
 */
static void
print_concise_mirror(int indent, mdsetname_t *sp, md_mirror_t *mirror)
{
	md_error_t	error = mdnullerror;
	int		i;
	md_status_t	status = mirror->common.state;

	if (mirror == NULL)
		return;

	print_concise_entry(indent, mirror->common.namep->cname,
	    mirror->common.size, 'm');

	for (i = 0; i < NMIRROR; i++) {
		uint_t	tstate = 0;
		char	*state;

		if (mirror->submirrors[i].submirnamep == NULL)
			continue;
		(void) printf(" %s", mirror->submirrors[i].submirnamep->cname);

		if (mirror->submirrors[i].state & SMS_OFFLINE) {
			(void) printf(gettext(" (offline)"));
			continue;
		}

		if (metaismeta(mirror->submirrors[i].submirnamep))
			(void) meta_get_tstate(
			    mirror->submirrors[i].submirnamep->dev,
			    &tstate, &error);

		state = get_sm_state(mirror, i, status, tstate);
		if (state != NULL)
			(void) printf(" (%s)", state);
	}

	(void) printf("\n");

	indent += META_INDENT;
	for (i = 0; i < NMIRROR; i++) {
		if (mirror->submirrors[i].submirnamep == NULL)
			continue;

		print_concise_md(indent, sp, mirror->submirrors[i].submirnamep);
	}
}

/*
 * Concise raid output.
 */
static void
print_concise_raid(int indent, mdsetname_t *sp, md_raid_t *raid)
{
	md_error_t	error = mdnullerror;
	int		i;
	uint_t		tstate = 0;

	if (raid == NULL)
		return;

	print_concise_entry(indent, raid->common.namep->cname,
	    raid->common.size, 'r');

	if (metaismeta(raid->common.namep))
		(void) meta_get_tstate(raid->common.namep->dev,
		    &tstate, &error);

	for (i = 0; i < raid->cols.cols_len; i++) {
		md_raidcol_t	*colp = &raid->cols.cols_val[i];
		mdname_t	*namep = ((colp->hsnamep != NULL) ?
		    colp->hsnamep : colp->colnamep);
		char	*hsname = ((colp->hsnamep != NULL) ?
		    colp->hsnamep->cname : NULL);
		char	*col_state = NULL;

		(void) printf(" %s", colp->colnamep->cname);

		if (metaismeta(namep)) {
			uint_t tstate = 0;

			(void) meta_get_tstate(namep->dev, &tstate, &error);
			col_state = get_raid_col_state(colp, tstate);

		} else {
			if (tstate != 0)
				col_state = "-";
			else
				col_state = get_raid_col_state(colp, tstate);
		}

		if (col_state != NULL) {
			if (hsname != NULL)
				(void) printf(" (%s-%s)", col_state, hsname);
			else
				(void) printf(" (%s)", col_state);

		} else if (hsname != NULL) {
			(void) printf(gettext(" (spared-%s)"), hsname);
		}
	}

	(void) printf("\n");

	indent += META_INDENT;
	for (i = 0; i < raid->cols.cols_len; i++) {
		print_concise_md(indent, sp, raid->cols.cols_val[i].colnamep);
	}
}

/*
 * Concise stripe output.
 */
static void
print_concise_stripe(int indent, mdsetname_t *sp, md_stripe_t *stripe)
{
	md_error_t	error = mdnullerror;
	int		i;
	uint_t		top_tstate = 0;

	if (stripe == NULL)
		return;

	print_concise_entry(indent, stripe->common.namep->cname,
	    stripe->common.size, 's');

	if (metaismeta(stripe->common.namep))
		(void) meta_get_tstate(stripe->common.namep->dev, &top_tstate,
		    &error);
	mdclrerror(&error);

	for (i = 0; i < stripe->rows.rows_len; i++) {
		md_row_t	*rowp;
		int		j;

		rowp = &stripe->rows.rows_val[i];

		for (j = 0; j < rowp->comps.comps_len; j++) {
			md_comp_t	*comp;
			uint_t		tstate = 0;
			char		*comp_state = NULL;
			char		*hsname;

			comp = &rowp->comps.comps_val[j];
			(void) printf(" %s", comp->compnamep->cname);

			if (metaismeta(comp->compnamep)) {
				uint_t tstate = 0;
				(void) meta_get_tstate(comp->compnamep->dev,
				    &tstate, &error);
				comp_state = get_stripe_state(comp, tstate);
			} else {
			if (top_tstate != 0)
				comp_state = "-";
			else
				comp_state = get_stripe_state(comp, tstate);
			}

			hsname = ((comp->hsnamep != NULL) ?
			    comp->hsnamep->cname : NULL);

			if (comp_state != NULL) {
				if (hsname != NULL)
					(void) printf(" (%s-%s)",
					    comp_state, hsname);
				else
					(void) printf(" (%s)", comp_state);

			} else if (hsname != NULL) {
				(void) printf(gettext(" (spared-%s)"), hsname);
			}
		}
	}

	(void) printf("\n");

	indent += META_INDENT;
	for (i = 0; i < stripe->rows.rows_len; i++) {
		md_row_t	*rowp;
		int		j;

		rowp = &stripe->rows.rows_val[i];

		for (j = 0; j < rowp->comps.comps_len; j++) {
			print_concise_md(indent, sp,
			    rowp->comps.comps_val[j].compnamep);
		}
	}
}

/*
 * Concise soft partition output.
 */
static void
print_concise_sp(int indent, mdsetname_t *sp, md_sp_t *part)
{
	if (part == NULL)
	return;

	print_concise_entry(indent, part->common.namep->cname,
	    part->common.size, 'p');

	(void) printf(" %s\n", part->compnamep->cname);

	print_concise_md(indent + META_INDENT, sp, part->compnamep);
}

/*
 * Concise trans output.
 */
static void
print_concise_trans(int indent, mdsetname_t *sp, md_trans_t *trans)
{
	if (trans == NULL)
		return;

	print_concise_entry(indent, trans->common.namep->cname,
	    trans->common.size, 't');

	if (trans->masternamep != NULL)
		(void) printf(" %s", trans->masternamep->cname);

	if (trans->lognamep != NULL)
		(void) printf(" %s", trans->lognamep->cname);

	(void) printf("\n");

	indent += META_INDENT;

	print_concise_md(indent, sp, trans->masternamep);

	print_concise_md(indent, sp, trans->lognamep);
}

/*
 * Recursive function for concise metadevice nested output.
 */
static void
print_concise_md(int indent, mdsetname_t *sp, mdname_t *np)
{
	md_error_t	error = mdnullerror;
	md_unit_t	*u;
	md_mirror_t	*mirror;
	md_raid_t	*raid;
	md_sp_t		*soft_part;
	md_stripe_t	*stripe;
	md_trans_t	*trans;

	if (np == NULL || !metaismeta(np))
		return;

	if ((u = meta_get_mdunit(sp, np, &error)) == NULL)
		return;

	switch (u->c.un_type) {
		case MD_DEVICE:
			stripe = meta_get_stripe_common(sp, np, 1, &error);
			print_concise_stripe(indent, sp, stripe);
			break;

		case MD_METAMIRROR:
			mirror = meta_get_mirror(sp, np, &error);
			print_concise_mirror(indent, sp, mirror);
			break;

		case MD_METATRANS:
			trans = meta_get_trans_common(sp, np, 1, &error);
			print_concise_trans(indent, sp, trans);
			break;

		case MD_METARAID:
			raid = meta_get_raid_common(sp, np, 1, &error);
			print_concise_raid(indent, sp, raid);
			break;

		case MD_METASP:
			soft_part = meta_get_sp_common(sp, np, 1, &error);
			print_concise_sp(indent, sp, soft_part);
			break;

		default:
			return;
	}
}

/*
 * Given a name get the unit for use in concise output.  We use the *_common
 * routines in libmeta which allow us to specify the "fast" flag, thereby
 * avoiding the DKIOCGGEOM ioctl that normally happens.
 */
static md_common_t *
get_concise_unit(mdsetname_t *sp, mdname_t *np, md_error_t *ep)
{
	char		*miscname;

	/* short circuit */
	if (np->drivenamep->unitp != NULL)
		return (np->drivenamep->unitp);
	if (metachkmeta(np, ep) != 0)
		return (NULL);

	/* dispatch */
	if ((miscname = metagetmiscname(np, ep)) == NULL)
		return (NULL);
	else if (strcmp(miscname, MD_STRIPE) == 0)
		return ((md_common_t *)meta_get_stripe_common(sp, np, 1, ep));
	else if (strcmp(miscname, MD_MIRROR) == 0)
		return ((md_common_t *)meta_get_mirror(sp, np, ep));
	else if (strcmp(miscname, MD_TRANS) == 0)
		return ((md_common_t *)meta_get_trans_common(sp, np, 1, ep));
	else if (strcmp(miscname, MD_RAID) == 0)
		return ((md_common_t *)meta_get_raid_common(sp, np, 1, ep));
	else if (strcmp(miscname, MD_SP) == 0)
		return ((md_common_t *)meta_get_sp_common(sp, np, 1, ep));
	else {
		(void) mdmderror(ep, MDE_UNKNOWN_TYPE, meta_getminor(np->dev),
		    np->cname);
		return (NULL);
	}
}

static void
free_names(mdnamelist_t **nlp)
{
	mdnamelist_t *p;

	for (p = *nlp; p != NULL; p = p->next) {
		meta_invalidate_name(p->namep);
		p->namep = NULL;
	}
	metafreenamelist(*nlp);
	*nlp = NULL;
}

/*
 * Submirror state for concise output.
 */
static char *
get_sm_state(md_mirror_t *mirror, int i, md_status_t mirror_status,
	uint_t tstate)
{
	sm_state_t	state = mirror->submirrors[i].state;
	uint_t	is_target =
	    mirror->submirrors[i].flags & MD_SM_RESYNC_TARGET;

	/*
	 * Only return Unavailable if there is no flagged error on the
	 * submirror. If the mirror has received any writes since the submirror
	 * went into Unavailable state a resync is required. To alert the
	 * administrator to this we return a 'Needs maintenance' message.
	 */
	if ((tstate != 0) && (state & SMS_RUNNING))
		return (gettext("unavail"));

	/* all is well */
	if (state & SMS_RUNNING) {
		if (!(mirror_status & MD_UN_OPT_NOT_DONE) ||
		    ((mirror_status & MD_UN_OPT_NOT_DONE) && !is_target))
			return (NULL);
	}

	/* resyncing, needs repair */
	if ((state & (SMS_COMP_RESYNC | SMS_ATTACHED_RESYNC |
	    SMS_OFFLINE_RESYNC)) || (mirror_status & MD_UN_OPT_NOT_DONE)) {
		static char buf[MAXPATHLEN];

		if (mirror_status & MD_UN_RESYNC_ACTIVE) {

			if (mirror->common.revision & MD_64BIT_META_DEV) {
				(void) snprintf(buf, sizeof (buf),
				    gettext("resync-%2d.%1d%%"),
				    mirror->percent_done / 10,
				    mirror->percent_done % 10);
			} else {
				(void) snprintf(buf, sizeof (buf),
				gettext("resync-%d%%"), mirror->percent_done);
			}
			return (buf);
		}
		return (gettext("maint"));
	}

	/* needs repair */
	if (state & (SMS_COMP_ERRED | SMS_ATTACHED | SMS_OFFLINE))
		return (gettext("maint"));

	/* unknown */
	return (gettext("unknown"));
}

/*
 * Raid component state for concise output.
 */
static char *
get_raid_col_state(md_raidcol_t *colp, uint_t tstate)
{
	if (tstate != 0)
		return (gettext("unavail"));

	return (meta_get_raid_col_state(colp->state));
}

/*
 * Stripe state for concise output.
 */
static char *
get_stripe_state(md_comp_t *mdcp, uint_t tstate)
{
	comp_state_t	state = mdcp->state;

	if (tstate != 0)
		return ("unavail");

	return (meta_get_stripe_state(state));
}

/*
 * Hostspare state for concise output.
 */
static char *
get_hs_state(md_hs_t *hsp)
{
	hotspare_states_t	state = hsp->state;

	return (meta_get_hs_state(state));
}


/*
 * Keep track of printed soft partitions for concise output.
 */
static struct sp_base_list *
sp_add_done(md_sp_t *part, struct sp_base_list *lp)
{
	struct sp_base_list *n;

	n = (struct sp_base_list *)malloc(sizeof (struct sp_base_list));
	if (n == NULL)
		return (lp);

	if ((n->base = strdup(part->compnamep->cname)) == NULL) {
		free(n);
		return (lp);
	}

	n->next = lp;

	return (n);
}

/*
 * Keep track of printed soft partitions for concise output.
 */
static int
sp_done(md_sp_t *part, struct sp_base_list *lp)
{
	for (; lp != NULL; lp = lp->next) {
		if (strcmp(lp->base, part->compnamep->cname) == 0)
			return (1);
	}

	return (0);
}

/*
 * Check the first element for a match.
 */
static int
sp_match(md_sp_t *part, struct sp_base_list *lp)
{
	if (lp != NULL && strcmp(lp->base, part->compnamep->cname) == 0)
		return (1);

	return (0);
}

/*
 * Free memory used for soft partition printed status in concise output.
 */
static void
sp_free_list(struct sp_base_list *lp)
{
	struct sp_base_list *n;

	for (; lp != NULL; lp = n) {
		n = lp->next;
		free(lp->base);
		free(lp);
	}
}
