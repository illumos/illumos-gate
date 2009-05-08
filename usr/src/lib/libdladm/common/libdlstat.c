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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <kstat.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <sys/dld.h>
#include <sys/ddi.h>

#include <libdllink.h>
#include <libdlflow.h>
#include <libdlstat.h>

/*
 * x86 <sys/regs> ERR conflicts with <curses.h> ERR.
 * Include curses.h last.
 */
#if	defined(ERR)
#undef  ERR
#endif
#include <curses.h>

struct flowlist {
	char		flowname[MAXFLOWNAMELEN];
	char		linkname[MAXLINKNAMELEN];
	datalink_id_t	linkid;
	int		fd;
	uint64_t	ifspeed;
	boolean_t	first;
	boolean_t	display;
	pktsum_t 	prevstats;
	pktsum_t	diffstats;
};

static	int	maxx, maxy, redraw = 0;
static	volatile uint_t handle_resize = 0, handle_break = 0;

pktsum_t		totalstats;
struct flowlist		*stattable = NULL;
static int		statentry = -1, maxstatentries = 0;

#define	STATGROWSIZE	16

/*
 * Search for flowlist entry in stattable which matches
 * the flowname and linkide.  If no match is found, use
 * next available slot.  If no slots are available,
 * reallocate table with  more slots.
 *
 * Return: *flowlist of matching flow
 *         NULL if realloc fails
 */

static struct flowlist *
findstat(const char *flowname, datalink_id_t linkid)
{
	int match = 0;
	struct flowlist *flist;

	/* Look for match in the stattable */
	for (match = 0, flist = stattable;
	    match <= statentry;
	    match++, flist++) {

		if (flist == NULL)
			break;
		/* match the flowname */
		if (flowname != NULL) {
			if (strncmp(flowname, flist->flowname, MAXFLOWNAMELEN)
			    == NULL)
				return (flist);
		/* match the linkid */
		} else {
			if (linkid == flist->linkid)
				return (flist);
		}
	}

	/*
	 * No match found in the table.  Store statistics in the next slot.
	 * If necessary, make room for this entry.
	 */
	statentry++;
	if ((maxstatentries == 0) || (maxstatentries == statentry)) {
		maxstatentries += STATGROWSIZE;
		stattable = realloc(stattable,
		    maxstatentries * sizeof (struct flowlist));
		if (stattable == NULL) {
			perror("realloc");
			return (struct flowlist *)(NULL);
		}
	}
	flist = &stattable[statentry];
	bzero(flist, sizeof (struct flowlist));

	if (flowname != NULL)
		(void) strncpy(flist->flowname, flowname, MAXFLOWNAMELEN);
	flist->linkid = linkid;
	flist->fd = INT32_MAX;

	return (flist);
}

/*ARGSUSED*/
static void
print_flow_stats(dladm_handle_t handle, struct flowlist *flist)
{
	struct flowlist *fcurr;
	double ikbs, okbs;
	double ipks, opks;
	double dlt;
	int fcount;
	static boolean_t first = B_TRUE;

	if (first) {
		first = B_FALSE;
		(void) printw("please wait...\n");
		return;
	}

	for (fcount = 0, fcurr = flist;
	    fcount <= statentry;
	    fcount++, fcurr++) {
		if (fcurr->flowname && fcurr->display) {
			dlt = (double)fcurr->diffstats.snaptime/(double)NANOSEC;
			ikbs = fcurr->diffstats.rbytes * 8 / dlt / 1024;
			okbs = fcurr->diffstats.obytes * 8 / dlt / 1024;
			ipks = fcurr->diffstats.ipackets / dlt;
			opks = fcurr->diffstats.opackets / dlt;
			(void) printw("%-15.15s", fcurr->flowname);
			(void) printw("%-10.10s", fcurr->linkname);
			(void) printw("%9.2f %9.2f %9.2f %9.2f ",
			    ikbs, okbs, ipks, opks);
			(void) printw("\n");
		}
	}
}

/*ARGSUSED*/
static int
flow_kstats(dladm_handle_t handle, dladm_flow_attr_t *attr, void *arg)
{
	kstat_ctl_t 	*kcp = (kstat_ctl_t *)arg;
	kstat_t		*ksp;
	struct flowlist	*flist;
	pktsum_t	currstats, *prevstats, *diffstats;

	flist = findstat(attr->fa_flowname, attr->fa_linkid);
	if (flist == NULL)
		return (DLADM_WALK_CONTINUE);

	flist->display = B_FALSE;
	prevstats = &flist->prevstats;
	diffstats = &flist->diffstats;

	(void) dladm_datalink_id2info(handle, attr->fa_linkid, NULL, NULL,
	    NULL, flist->linkname, sizeof (flist->linkname));


	/* lookup kstat entry */
	ksp = dladm_kstat_lookup(kcp, NULL, -1, attr->fa_flowname, "flow");

	if (ksp == NULL)
		return (DLADM_WALK_CONTINUE);

	/* read packet and byte stats */
	dladm_get_stats(kcp, ksp, &currstats);

	if (flist->ifspeed == 0)
		(void) dladm_kstat_value(ksp, "ifspeed", KSTAT_DATA_UINT64,
		    &flist->ifspeed);

	if (flist->first) {
		flist->first = B_FALSE;
	} else {
		dladm_stats_diff(diffstats, &currstats, prevstats);
		if (diffstats->snaptime == 0)
			return (DLADM_WALK_CONTINUE);
		dladm_stats_total(&totalstats, diffstats, &totalstats);
	}

	bcopy(&currstats, prevstats, sizeof (pktsum_t));
	flist->display = B_TRUE;

	return (DLADM_WALK_CONTINUE);
}

/*ARGSUSED*/
static void
print_link_stats(dladm_handle_t handle, struct flowlist *flist)
{
	struct flowlist *fcurr;
	double ikbs, okbs;
	double ipks, opks;
	double util;
	double dlt;
	int fcount;
	static boolean_t first = B_TRUE;

	if (first) {
		first = B_FALSE;
		(void) printw("please wait...\n");
		return;
	}

	for (fcount = 0, fcurr = flist;
	    fcount <= statentry;
	    fcount++, fcurr++) {
		if ((fcurr->linkid != DATALINK_INVALID_LINKID) &&
		    fcurr->display)  {
			dlt = (double)fcurr->diffstats.snaptime/(double)NANOSEC;
			ikbs = (double)fcurr->diffstats.rbytes * 8 / dlt / 1024;
			okbs = (double)fcurr->diffstats.obytes * 8 / dlt / 1024;
			ipks = (double)fcurr->diffstats.ipackets / dlt;
			opks = (double)fcurr->diffstats.opackets / dlt;
			(void) printw("%-10.10s", fcurr->linkname);
			(void) printw("%9.2f %9.2f %9.2f %9.2f ",
			    ikbs, okbs, ipks, opks);
			if (fcurr->ifspeed != 0)
				util = ((ikbs + okbs) * 1024) *
				    100/ fcurr->ifspeed;
			else
				util = (double)0;
			(void) attron(A_BOLD);
			(void) printw("    %6.2f", util);
			(void) attroff(A_BOLD);
			(void) printw("\n");
		}
	}
}

/*
 * This function is called through the dladm_walk_datalink_id() walker and
 * calls the dladm_walk_flow() walker.
 */

/*ARGSUSED*/
static int
link_flowstats(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	dladm_status_t	status;

	status = dladm_walk_flow(flow_kstats, handle, linkid, arg, B_FALSE);
	if (status == DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);
	else
		return (DLADM_WALK_TERMINATE);
}

/*ARGSUSED*/
static int
link_kstats(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	kstat_ctl_t		*kcp = (kstat_ctl_t *)arg;
	struct flowlist		*flist;
	pktsum_t		currstats, *prevstats, *diffstats;
	datalink_class_t	class;
	kstat_t			*ksp;
	char			dnlink[MAXPATHLEN];

	/* find the flist entry */
	flist = findstat(NULL, linkid);
	flist->display = B_FALSE;
	if (flist != NULL) {
		prevstats = &flist->prevstats;
		diffstats = &flist->diffstats;
	} else {
		return (DLADM_WALK_CONTINUE);
	}

	if (dladm_datalink_id2info(handle, linkid, NULL, &class, NULL,
	    flist->linkname, sizeof (flist->linkname)) != DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	if (flist->fd == INT32_MAX) {
		if (class == DATALINK_CLASS_PHYS) {
			(void) snprintf(dnlink, MAXPATHLEN, "/dev/net/%s",
			    flist->linkname);
			if ((flist->fd = open(dnlink, O_RDWR)) < 0)
				return (DLADM_WALK_CONTINUE);
		} else {
			flist->fd = -1;
		}
		(void) kstat_chain_update(kcp);
	}

	/* lookup kstat entry */
	ksp = dladm_kstat_lookup(kcp, NULL, -1, flist->linkname, "net");

	if (ksp == NULL)
		return (DLADM_WALK_CONTINUE);

	/* read packet and byte stats */
	dladm_get_stats(kcp, ksp, &currstats);

	if (flist->ifspeed == 0)
		(void) dladm_kstat_value(ksp, "ifspeed", KSTAT_DATA_UINT64,
		    &flist->ifspeed);

	if (flist->first) {
		flist->first = B_FALSE;
	} else {
		dladm_stats_diff(diffstats, &currstats, prevstats);
		if (diffstats->snaptime == 0)
			return (DLADM_WALK_CONTINUE);
	}

	bcopy(&currstats, prevstats, sizeof (*prevstats));
	flist->display = B_TRUE;

	return (DLADM_WALK_CONTINUE);
}

static void
closedevnet()
{
	int index = 0;
	struct flowlist *flist;

	/* Close all open /dev/net/ files */
	for (flist = stattable; index <= maxstatentries; index++, flist++) {
		if (flist->linkid == DATALINK_INVALID_LINKID)
			break;
		if (flist->fd != -1 && flist->fd != INT32_MAX)
			(void) close(flist->fd);
	}
}

/*ARGSUSED*/
static void
sig_break(int s)
{
	handle_break = 1;
}

/*ARGSUSED*/
static void
sig_resize(int s)
{
	handle_resize = 1;
}

static void
curses_init()
{
	maxx = maxx;	/* lint */
	maxy = maxy;	/* lint */

	/* Install signal handlers */
	(void) signal(SIGINT,  sig_break);
	(void) signal(SIGQUIT, sig_break);
	(void) signal(SIGTERM, sig_break);
	(void) signal(SIGWINCH, sig_resize);

	/* Initialize ncurses */
	(void) initscr();
	(void) cbreak();
	(void) noecho();
	(void) curs_set(0);
	timeout(0);
	getmaxyx(stdscr, maxy, maxx);
}

static void
curses_fin()
{
	(void) printw("\n");
	(void) curs_set(1);
	(void) nocbreak();
	(void) endwin();

	free(stattable);
}

static void
stat_report(dladm_handle_t handle, kstat_ctl_t *kcp,  datalink_id_t linkid,
    const char *flowname, int opt)
{

	double dlt, ikbs, okbs, ipks, opks;

	struct flowlist *fstable = stattable;

	if ((opt != LINK_REPORT) && (opt != FLOW_REPORT))
		return;

	/* Handle window resizes */
	if (handle_resize) {
		(void) endwin();
		(void) initscr();
		(void) cbreak();
		(void) noecho();
		(void) curs_set(0);
		timeout(0);
		getmaxyx(stdscr, maxy, maxx);
		redraw = 1;
		handle_resize = 0;
	}

	/* Print title */
	(void) erase();
	(void) attron(A_BOLD);
	(void) move(0, 0);
	if (opt == FLOW_REPORT)
		(void) printw("%-15.15s", "Flow");
	(void) printw("%-10.10s", "Link");
	(void) printw("%9.9s %9.9s %9.9s %9.9s ",
	    "iKb/s", "oKb/s", "iPk/s", "oPk/s");
	if (opt == LINK_REPORT)
		(void) printw("    %6.6s", "%Util");
	(void) printw("\n");
	(void) attroff(A_BOLD);

	(void) move(2, 0);

	/* Print stats for each link or flow */
	bzero(&totalstats, sizeof (totalstats));
	if (opt == LINK_REPORT) {
		/* Display all links */
		if (linkid == DATALINK_ALL_LINKID) {
			(void) dladm_walk_datalink_id(link_kstats, handle,
			    (void *)kcp, DATALINK_CLASS_ALL,
			    DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
		/* Display 1 link */
		} else {
			(void) link_kstats(handle, linkid, kcp);
		}
		print_link_stats(handle, fstable);

	} else if (opt == FLOW_REPORT) {
		/* Display 1 flow */
		if (flowname != NULL) {
			dladm_flow_attr_t fattr;
			if (dladm_flow_info(handle, flowname, &fattr) !=
			    DLADM_STATUS_OK)
				return;
			(void) flow_kstats(handle, &fattr, kcp);
		/* Display all flows on all links */
		} else if (linkid == DATALINK_ALL_LINKID) {
			(void) dladm_walk_datalink_id(link_flowstats, handle,
			    (void *)kcp, DATALINK_CLASS_ALL,
			    DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
		/* Display all flows on a link */
		} else if (linkid != DATALINK_INVALID_LINKID) {
			(void) dladm_walk_flow(flow_kstats, handle, linkid, kcp,
			    B_FALSE);
		}
		print_flow_stats(handle, fstable);

		/* Print totals */
		(void) attron(A_BOLD);
		dlt = (double)totalstats.snaptime / (double)NANOSEC;
		ikbs = totalstats.rbytes / dlt / 1024;
		okbs = totalstats.obytes / dlt / 1024;
		ipks = totalstats.ipackets / dlt;
		opks = totalstats.opackets / dlt;
		(void) printw("\n%-25.25s", "Totals");
		(void) printw("%9.2f %9.2f %9.2f %9.2f ",
		    ikbs, okbs, ipks, opks);
		(void) attroff(A_BOLD);
	}

	if (redraw)
		(void) clearok(stdscr, 1);

	if (refresh() == ERR)
		return;

	if (redraw) {
		(void) clearok(stdscr, 0);
		redraw = 0;
	}
}

/* Exported functions */

/*
 * Continuously display link or flow statstics using a libcurses
 * based display.
 */

void
dladm_continuous(dladm_handle_t handle, datalink_id_t linkid,
    const char *flowname, int interval, int opt)
{
	kstat_ctl_t *kcp;

	if ((kcp = kstat_open()) == NULL) {
		warn("kstat open operation failed");
		return;
	}

	curses_init();

	for (;;) {

		if (handle_break)
			break;

		stat_report(handle, kcp, linkid, flowname, opt);

		(void) sleep(max(1, interval));
	}

	closedevnet();
	curses_fin();
	(void) kstat_close(kcp);
}

/*
 * dladm_kstat_lookup() is a modified version of kstat_lookup which
 * adds the class as a selector.
 */

kstat_t *
dladm_kstat_lookup(kstat_ctl_t *kcp, const char *module, int instance,
    const char *name, const char *class)
{
	kstat_t *ksp = NULL;

	for (ksp = kcp->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
		if ((module == NULL || strcmp(ksp->ks_module, module) == 0) &&
		    (instance == -1 || ksp->ks_instance == instance) &&
		    (name == NULL || strcmp(ksp->ks_name, name) == 0) &&
		    (class == NULL || strcmp(ksp->ks_class, class) == 0))
			return (ksp);
	}

	errno = ENOENT;
	return (NULL);
}

/*
 * dladm_get_stats() populates the supplied pktsum_t structure with
 * the input and output  packet and byte kstats from the kstat_t
 * found with dladm_kstat_lookup.
 */
void
dladm_get_stats(kstat_ctl_t *kcp, kstat_t *ksp, pktsum_t *stats)
{

	if (kstat_read(kcp, ksp, NULL) == -1)
		return;

	stats->snaptime = gethrtime();

	if (dladm_kstat_value(ksp, "ipackets64", KSTAT_DATA_UINT64,
	    &stats->ipackets) < 0) {
		if (dladm_kstat_value(ksp, "ipackets", KSTAT_DATA_UINT64,
		    &stats->ipackets) < 0)
			return;
	}

	if (dladm_kstat_value(ksp, "opackets64", KSTAT_DATA_UINT64,
	    &stats->opackets) < 0) {
		if (dladm_kstat_value(ksp, "opackets", KSTAT_DATA_UINT64,
		    &stats->opackets) < 0)
			return;
	}

	if (dladm_kstat_value(ksp, "rbytes64", KSTAT_DATA_UINT64,
	    &stats->rbytes) < 0) {
		if (dladm_kstat_value(ksp, "rbytes", KSTAT_DATA_UINT64,
		    &stats->rbytes) < 0)
			return;
	}

	if (dladm_kstat_value(ksp, "obytes64", KSTAT_DATA_UINT64,
	    &stats->obytes) < 0) {
		if (dladm_kstat_value(ksp, "obytes", KSTAT_DATA_UINT64,
		    &stats->obytes) < 0)
			return;
	}

	if (dladm_kstat_value(ksp, "ierrors", KSTAT_DATA_UINT32,
	    &stats->ierrors) < 0) {
		if (dladm_kstat_value(ksp, "ierrors", KSTAT_DATA_UINT64,
		    &stats->ierrors) < 0)
		return;
	}

	if (dladm_kstat_value(ksp, "oerrors", KSTAT_DATA_UINT32,
	    &stats->oerrors) < 0) {
		if (dladm_kstat_value(ksp, "oerrors", KSTAT_DATA_UINT64,
		    &stats->oerrors) < 0)
			return;
	}
}

int
dladm_kstat_value(kstat_t *ksp, const char *name, uint8_t type, void *buf)
{
	kstat_named_t	*knp;

	if ((knp = kstat_data_lookup(ksp, (char *)name)) == NULL)
		return (-1);

	if (knp->data_type != type)
		return (-1);

	switch (type) {
	case KSTAT_DATA_UINT64:
		*(uint64_t *)buf = knp->value.ui64;
		break;
	case KSTAT_DATA_UINT32:
		*(uint32_t *)buf = knp->value.ui32;
		break;
	default:
		return (-1);
	}

	return (0);
}

dladm_status_t
dladm_get_single_mac_stat(dladm_handle_t handle, datalink_id_t linkid,
    const char *name, uint8_t type, void *val)
{
	kstat_ctl_t	*kcp;
	char		module[DLPI_LINKNAME_MAX];
	uint_t		instance;
	char 		link[DLPI_LINKNAME_MAX];
	dladm_status_t	status;
	uint32_t	flags, media;
	kstat_t		*ksp;
	dladm_phys_attr_t dpap;

	if ((status = dladm_datalink_id2info(handle, linkid, &flags, NULL,
	    &media, link, DLPI_LINKNAME_MAX)) != DLADM_STATUS_OK)
		return (status);

	if (media != DL_ETHER)
		return (DLADM_STATUS_LINKINVAL);

	status = dladm_phys_info(handle, linkid, &dpap, DLADM_OPT_PERSIST);

	if (status != DLADM_STATUS_OK)
		return (status);

	status = dladm_parselink(dpap.dp_dev, module, &instance);

	if (status != DLADM_STATUS_OK)
		return (status);

	if ((kcp = kstat_open()) == NULL) {
		warn("kstat_open operation failed");
		return (-1);
	}

	/*
	 * The kstat query could fail if the underlying MAC
	 * driver was already detached.
	 */
	if ((ksp = kstat_lookup(kcp, module, instance, "mac")) == NULL &&
	    (ksp = kstat_lookup(kcp, module, instance, NULL)) == NULL)
		goto bail;

	if (kstat_read(kcp, ksp, NULL) == -1)
		goto bail;

	if (dladm_kstat_value(ksp, name, type, val) < 0)
		goto bail;

	(void) kstat_close(kcp);
	return (DLADM_STATUS_OK);

bail:
	(void) kstat_close(kcp);
	return (dladm_errno2status(errno));
}

/* Compute sum of 2 pktsums (s1 = s2 + s3) */
void
dladm_stats_total(pktsum_t *s1, pktsum_t *s2, pktsum_t *s3)
{
	s1->rbytes    = s2->rbytes    + s3->rbytes;
	s1->ipackets  = s2->ipackets  + s3->ipackets;
	s1->ierrors   = s2->ierrors   + s3->ierrors;
	s1->obytes    = s2->obytes    + s3->obytes;
	s1->opackets  = s2->opackets  + s3->opackets;
	s1->oerrors   = s2->oerrors   + s3->oerrors;
	s1->snaptime  = s2->snaptime;
}

#define	DIFF_STAT(s2, s3) ((s2) > (s3) ? (s2 - s3) : 0)


/* Compute differences between 2 pktsums (s1 = s2 - s3) */
void
dladm_stats_diff(pktsum_t *s1, pktsum_t *s2, pktsum_t *s3)
{
	s1->rbytes    = DIFF_STAT(s2->rbytes,   s3->rbytes);
	s1->ipackets  = DIFF_STAT(s2->ipackets, s3->ipackets);
	s1->ierrors   = DIFF_STAT(s2->ierrors,  s3->ierrors);
	s1->obytes    = DIFF_STAT(s2->obytes,   s3->obytes);
	s1->opackets  = DIFF_STAT(s2->opackets, s3->opackets);
	s1->oerrors   = DIFF_STAT(s2->oerrors,  s3->oerrors);
	s1->snaptime  = DIFF_STAT(s2->snaptime, s3->snaptime);
}
