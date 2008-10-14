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

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/nsctl/sdbc_ioctl.h>
#include <sys/nsctl/rdc_ioctl.h>
#include <sys/nsctl/sd_bcache.h>
#include <sys/nsctl/sd_conf.h>
#include <sys/nsctl/rdc_io.h>
#include <sys/nsctl/rdc_bitmap.h>
#include <sys/unistat/spcs_s_u.h>
#include <curses.h>

static rdc_status_t *rdc_status;
static rdc_u_info_t *rdc_info;
static int rdc_maxsets;
static int rdc_enabled_sets;

static unsigned prev_time, delta_time;
#ifdef m88k
extern unsigned *usec_ptr;
#endif
static int bright = 0;

extern int sdbc_max_devices;

extern _sd_stats_t *cs_cur;
extern _sd_stats_t *cs_prev;
extern _sd_stats_t *cs_persec;

extern int *on_off;
extern int *dual_on_off;
extern int *updates_prev;
extern double *rate_prev;
extern int *samples;

int		range_num = 0;
int		screen = 0;
int		dual_screen = 0;
static		int rnum = 0;

typedef struct {
	int lb, ub;
} range_t;
range_t ranges[100];

extern int range_first();
extern int range_next(int);
extern int range_last();

static int dual_initted = 0;
static char status[11][30];

unsigned dc_delta_time, dc_prev_time;

#ifdef m88k
#define	USEC_INIT()	usec_ptr = (unsigned int *)timer_init()
#define	USEC_READ()	(*usec_ptr)
#else /* !m88k */
#define	USEC_INIT()	USEC_START()
#include <sys/time.h>
static struct timeval Usec_time;
static int Usec_started = 0;

void total_display(void);
void disp_stats(void);
void do_calc(void);
void init_dual(void);
void calc_time(void);
void calc_completion(int, int, int);
void disp_total_stats(void);
void display_cache(void);

#define	DISPLEN 16

static void
USEC_START(void)
{
	if (!Usec_started) {
		(void) gettimeofday(&Usec_time, NULL);
		Usec_started = 1;
	}
}

static unsigned int
USEC_READ()
{
	struct timeval tv;
	if (!Usec_started)
		USEC_START();

	(void) gettimeofday(&tv, NULL);
	return (unsigned)((tv.tv_sec - Usec_time.tv_sec) * 1000000 +
	    (tv.tv_usec - Usec_time.tv_usec));
}
#endif /* m88k */

#define	SAMPLE_RATE 5

/*
 * refresh curses window to file
 */
void
wrefresh_file(WINDOW *win, int fd)
{
	char buf[8192], c, *cp = buf, *line, *blank, *empty;
	int x, y;

	empty = NULL;		/* cull trailing empty lines */
	for (y = 0; y < win->_maxy; y++) {
		line = cp;
		blank = NULL;	/* cull trailing blanks */
		for (x = 0; x < win->_maxx; x++) {
			c = (win->_y[y][x]) & A_CHARTEXT;
			if (c != ' ')
				blank = NULL;
			else if (blank == NULL)
				blank = cp;
			*cp++ = c;
		}
		if (blank)
			cp = blank;
		if (line != cp)
			empty = NULL;
		else if (empty == NULL)
			empty = cp + 1;
		*cp++ = '\n';
	}
	if (empty)
		cp = empty;
	*cp++ = '\f'; *cp++ = '\n'; *cp = '\0';
	/* cp is eliminated by short _maxy and _maxx, it won't overflow */
	/* LINTED, cp - buf won't be > INT32_MAX */
	(void) write(fd, buf, cp - buf);
}


int
higher(int high)
{
	int i;

	for (i = high + 1; i <= sdbc_max_devices; i++) {
		if (cs_cur->st_shared[i].sh_alloc)
			return (i);
	}
	return (0);
}

int
is_dirty()
{
	int i, dirty = 0;
	spcs_s_info_t ustats;

	if (SDBC_IOCTL(SDBC_STATS, cs_cur, 0, 0, 0, 0,
	    &ustats) == SPCS_S_ERROR) {
		perror("Could not get stats from kernel");
		if (ustats) {
			spcs_s_report(ustats, stderr);
			spcs_s_ufree(&ustats);
		}
		return (-errno);
	}
	if (cs_cur->st_cachesize == 0)
		return (0);

	for (i = 0; i < cs_cur->st_count; i++)  {
		if (cs_cur->st_shared[i].sh_alloc)
			dirty += cs_cur->st_shared[i].sh_numdirty;
	}

	return (dirty != 0);
}

void
display_cache(void)
{
	static int first = 1;
	spcs_s_info_t ustats;

	if (SDBC_IOCTL(SDBC_STATS, cs_cur, 0, 0, 0, 0, &ustats) ==
	    SPCS_S_ERROR) {
		perror("sd_stats");
		if (ustats) {
			spcs_s_report(ustats, stderr);
			spcs_s_ufree(&ustats);
		}
	}

	do_calc();
	if (first) {
		prev_time = USEC_READ();
		first = 0;
	} else
		disp_stats();
}

void
total_display(void)
{
	spcs_s_info_t ustats;

	if (SDBC_IOCTL(SDBC_STATS, cs_cur, 0, 0, 0, 0, &ustats) ==
	    SPCS_S_ERROR) {
		if (ustats) {
			spcs_s_report(ustats, stderr);
			spcs_s_ufree(&ustats);
		}
		perror("sd_stats");
	}
	disp_total_stats();
}


int
range_first()
{
	rnum = 0;
	return (ranges[rnum].lb);
}

int
range_next(int cd)
{
	if (ranges[rnum].ub > cd)
		return (cd + 1);
	if (range_num > rnum)
		rnum++;
	else
		return (cd + 1);
	return (ranges[rnum].lb);
}

int
range_last() {
	return (ranges[range_num].ub);
}


void
set_dual_on_off()
{
	int i, j, ct = 0, newct = 0;

	for (i = range_first(); i < rdc_enabled_sets && i <= range_last();
	    i = range_next(i)) {
		if (rdc_info[i].flags & RDC_ENABLED) {
			ct++;
			if (ct > dual_screen * ((LINES - 9) / 2))
				break;
		}
	}
	if (((i >= rdc_enabled_sets) ||
	    (i > range_last())) && (dual_screen > 0)) {
		dual_screen--;
		set_dual_on_off();
	} else {
		bzero(dual_on_off, sdbc_max_devices * sizeof (int));
		for (j = i; j < rdc_enabled_sets && j <= range_last();
		    j = range_next(j)) {
			if (rdc_info[j].flags & RDC_ENABLED) {
				newct++;
				if (newct <= (LINES - 9) / 2) {
					dual_on_off[j] = 1;
				} else
					break;
			}
		}
	}
}


void
set_on_off()
{
	int i, j, ct = 0, newct = 0;

	for (i = range_first(); i <= range_last(); i = range_next(i)) {
		if (cs_cur->st_shared[i].sh_alloc) {
			ct++;
			if (ct > screen*((LINES - 9) / 2))
				break;
		}
	}
	if ((i > range_last()) && (screen > 0)) {
		screen--;
		set_on_off();
	} else {
		bzero(on_off, sdbc_max_devices * sizeof (int));
		for (j = i; j <= range_last(); j = range_next(j)) {
			if (cs_cur->st_shared[j].sh_alloc) {
				newct++;
				if (newct <= (LINES - 9) / 2)
					on_off[j] = 1;
				else
					break;
			}
		}
	}
}

void
disp_stats(void)
{
	double	read_s, write_s, access_s, readp, writep;
	double	rmiss_s, wmiss_s;
	double	elapsed = delta_time / 1000000.0;
	double  kbps = elapsed * 1024.0; /* for Kbytes per second */
	int	rtotal, wtotal, i, j;
	double	throughput = 0.0, rthroughput = 0.0;
	double	creads = 0.0, cwrites = 0.0;
	char	status_bit, down = 0;
	int	len;
	char	fn[19];

	if (delta_time != 0) {
		read_s  = cs_persec->st_rdhits / elapsed;
		write_s = cs_persec->st_wrhits / elapsed;
		rmiss_s = cs_persec->st_rdmiss / elapsed;
		wmiss_s = cs_persec->st_wrmiss / elapsed;
		access_s = (cs_persec->st_wrhits + cs_persec->st_rdhits +
		    cs_persec->st_rdmiss + cs_persec->st_wrmiss) / elapsed;
	} else
		read_s = write_s = access_s = 0.0;

	rtotal = cs_persec->st_rdhits + cs_persec->st_rdmiss;
	wtotal = cs_persec->st_wrhits + cs_persec->st_wrmiss;
	if (rtotal != 0)
		readp = cs_persec->st_rdhits / (double)rtotal;
	else
		readp = 0.0;

	if (wtotal != 0) {
		writep = cs_persec->st_wrhits / (double)wtotal;
	} else
		writep = 0.0;

	set_on_off();
	if (cs_cur->st_cachesize == 0)
		(void) mvprintw(0, 20, "****** Storage Cache Disabled ******");
	else
		(void) mvprintw(0, 20, "******      Storage Cache     ******");
	(void) mvprintw(2, 26, "disk_io       cache          write_blocks");
	(void) attron(A_UNDERLINE);
	(void) mvprintw(3, 1, " cd cached_partition  reads writes  reads writes"
	    "  dirty todisk failed");
	(void) attroff(A_UNDERLINE);
	for (i = 0, j = 0; j < cs_cur->st_count; i++) {
		if (i >= sdbc_max_devices)
			break;
		if (cs_cur->st_shared[i].sh_alloc)  {
			cs_persec->st_shared[i].sh_disk_write /= kbps;
			cs_persec->st_shared[i].sh_disk_read  /= kbps;
			cs_persec->st_shared[i].sh_cache_write /= kbps;
			cs_persec->st_shared[i].sh_cache_read /= kbps;
			rthroughput += cs_persec->st_shared[i].sh_disk_read;
			throughput += cs_persec->st_shared[i].sh_disk_write;
			creads += cs_persec->st_shared[i].sh_cache_read;
			cwrites += cs_persec->st_shared[i].sh_cache_write;
			if (!down)
				down = cs_cur->st_shared[i].sh_failed;
			if (cs_cur->st_shared[i].sh_failed && bright) {
				status_bit = '*';
			} else
				status_bit = ' ';
			if ((len = strlen(cs_cur->st_shared[i].sh_filename))
			    > 15) {
				strcpy(fn, "...");
				strcat(fn, cs_cur->st_shared[i].sh_filename +
				    len - 12);
			} else
				strcpy(fn, cs_cur->st_shared[i].sh_filename);
			if (on_off[i]) {
				(void) mvprintw(4 + j, 1,
				    "%3d %-15s%c %6d %6d %6d %6d %6d %6d %6d",
				    cs_cur->st_shared[i].sh_cd,
				    fn,
				    status_bit,
				    cs_persec->st_shared[i].sh_disk_read,
				    cs_persec->st_shared[i].sh_disk_write,
				    cs_persec->st_shared[i].sh_cache_read,
				    cs_persec->st_shared[i].sh_cache_write,
				    cs_cur->st_shared[i].sh_numdirty,
				    cs_cur->st_shared[i].sh_numio,
				    cs_cur->st_shared[i].sh_numfail);
				j++;
			}
		}
	}
	bright = !bright;

	(void) mvprintw(4 + j, 22, "------ ------ ------ ------");
	(void) mvprintw(5 + j, 6, " Kbytes/s total:%6d %6d %6d %6d",
	    (int)rthroughput, (int)throughput,
	    (int)creads, (int)cwrites);
	(void) mvprintw(7 + j, 1, "accesses/s");
	(void) mvprintw(7 + j, 15, "read/s    write/s   %%readh   %%writeh");

	(void) attron(A_UNDERLINE);
	(void) mvprintw(8 + j, 1, "            ");
	(void) mvprintw(8 + j, 13,
	    "                                                ");
	(void) mvprintw(8 + j, 13, "(misses/s) (misses/s)");
	(void) attroff(A_UNDERLINE);

	(void) mvprintw(9 + j, 0, "%10.2lf    %7.2f    %7.2f   %6.1f    %6.1f",
	    access_s, read_s, write_s, readp * 100.0, writep * 100.0);
	(void) mvprintw(10 + j, 0, "             (%7.2f ) (%7.2f )\n\n",
	    rmiss_s, wmiss_s);

	if (down)
		(void) mvprintw(20 + j, 1, "* -- disk off-line");
}

void
do_calc(void)
{
	int i, j;

	delta_time = USEC_READ() - prev_time;

	cs_persec->st_rdhits = cs_cur->st_rdhits - cs_prev->st_rdhits;
	cs_persec->st_rdmiss = cs_cur->st_rdmiss - cs_prev->st_rdmiss;
	cs_persec->st_wrhits = cs_cur->st_wrhits - cs_prev->st_wrhits;
	cs_persec->st_wrmiss = cs_cur->st_wrmiss - cs_prev->st_wrmiss;

	for (i = 0, j = 0; j < cs_cur->st_count; i++) {
		if (i >= sdbc_max_devices)
			break;
		if (cs_cur->st_shared[i].sh_alloc) {
			cs_persec->st_shared[i].sh_disk_write =
			    FBA_SIZE(cs_cur->st_shared[i].sh_disk_write -
			    cs_prev->st_shared[i].sh_disk_write);
			cs_persec->st_shared[i].sh_disk_read =
			    FBA_SIZE(cs_cur->st_shared[i].sh_disk_read -
			    cs_prev->st_shared[i].sh_disk_read);
			cs_persec->st_shared[i].sh_cache_read =
			    FBA_SIZE(cs_cur->st_shared[i].sh_cache_read -
			    cs_prev->st_shared[i].sh_cache_read);
			cs_persec->st_shared[i].sh_cache_write =
			    FBA_SIZE(cs_cur->st_shared[i].sh_cache_write -
			    cs_prev->st_shared[i].sh_cache_write);
			j++;
		}
	}
	(void) memcpy((char *) cs_prev, (char *) cs_cur, sizeof (_sd_stats_t) +
	    (sdbc_max_devices - 1) * sizeof (_sd_shared_t));
	prev_time = USEC_READ();
}


void
init_dual(void)
{
#define	IND_ENABLED		0
#define	IND_RESYNC  		1
#define	IND_RESYNC_REVERSE	2
#define	IND_VOLUME_DOWN		3
#define	IND_MIRROR_DOWN		4
#define	IND_LOGGING		5
#define	IND_RESYNC_NEEDED	6
#define	IND_REV_RESYNC_NEEDED	7
#define	IND_BITMAP_FAILED	8
#define	IND_FULL_SYNC_NEEDED	9
#define	IND_FCAL_FAILED		10
	strcpy(status[IND_ENABLED], "replicating");
	strcpy(status[IND_RESYNC], "sync");
	strcpy(status[IND_RESYNC_REVERSE], "rev sync");
	strcpy(status[IND_VOLUME_DOWN], "volume down");
	strcpy(status[IND_MIRROR_DOWN], "mirror down");
	strcpy(status[IND_LOGGING], "logging");
	strcpy(status[IND_RESYNC_NEEDED], "need sync");
	strcpy(status[IND_REV_RESYNC_NEEDED], "need rev sync");
	strcpy(status[IND_BITMAP_FAILED], "bitmap failed");
	strcpy(status[IND_FULL_SYNC_NEEDED], "full sync needed");
	strcpy(status[IND_FCAL_FAILED], "fcal failed");
	dual_initted = 1;
}


int
rdc_get_maxsets(void)
{
	rdc_status_t rdc_status;
	spcs_s_info_t ustatus;
	int rc;

	rdc_status.nset = 0;
	ustatus = spcs_s_ucreate();

	rc = RDC_IOCTL(RDC_STATUS, &rdc_status, 0, 0, 0, 0, ustatus);
	spcs_s_ufree(&ustatus);

	if (rc == SPCS_S_ERROR)
		return (-1);

	return (rdc_status.maxsets);
}

int
dual_stats()
{
	int ind, i, k, len;
	int stars, size, segs;
	int rdcindex;
	float pct;
	char	fn[19];
	char *phost;
	char *shost;
	char *pfile;
	char *sfile;
	char lhost[16];
	spcs_s_info_t ustats = NULL;

	(void) gethostname(lhost, 16);

	if (rdc_maxsets <= 0)
		rdc_maxsets = rdc_get_maxsets();

	if (rdc_maxsets < 0)
		goto no_stats;

	if (!rdc_status) {
		rdc_status = malloc(sizeof (rdc_status_t) +
			(sizeof (rdc_set_t) * (rdc_maxsets - 1)));
		if (!rdc_status) {
no_stats:
			(void) mvprintw(0, 20,
				"****** Dual Copy Not Available ******");
			return (-1);
		}

		rdc_info = rdc_status->rdc_set;
	}

	rdc_status->nset = rdc_maxsets;
	ustats = spcs_s_ucreate();

	size = RDC_IOCTL(RDC_STATUS, rdc_status, 0, 0, 0, 0, ustats);
	if (size == SPCS_S_ERROR) {
		if (ustats) {
			spcs_s_report(ustats, stderr);
			spcs_s_ufree(&ustats);
		}
		(void) mvprintw(0, 20, "****** Dual Copy Not Available ******");
		return (-1);
	}
	spcs_s_ufree(&ustats);
	rdc_enabled_sets = rdc_status->nset;

	if (!dual_initted)
		init_dual();

	set_dual_on_off();

	calc_time();

	(void) mvprintw(0, 20, "****** Dual Copy Statistics ******");
	(void) attron(A_UNDERLINE);
	(void) mvprintw(2,  0, "primary");
	(void) mvprintw(2, 22, "link status");
	(void) mvprintw(2, 36, "secondary");
	(void) mvprintw(2, 54, "dual copy status");
	(void) attroff(A_UNDERLINE);

	for (rdcindex = 0, k = 0; rdcindex < rdc_enabled_sets; rdcindex++)  {
		if (!(rdc_info[rdcindex].flags & RDC_ENABLED) ||
		    !dual_on_off[rdcindex])
			continue;

		if (rdc_info[rdcindex].sync_flags & RDC_VOL_FAILED)
			ind = IND_VOLUME_DOWN;
		else if (rdc_info[rdcindex].flags & RDC_FCAL_FAILED)
			ind = IND_FCAL_FAILED;
		else if (rdc_info[rdcindex].bmap_flags & RDC_BMP_FAILED)
			ind = IND_BITMAP_FAILED;
		else if (rdc_info[rdcindex].flags & RDC_LOGGING) {
			if (rdc_info[rdcindex].sync_flags &
			    RDC_SYNC_NEEDED)
				ind = IND_RESYNC_NEEDED;
			else if (rdc_info[rdcindex].sync_flags &
			    RDC_RSYNC_NEEDED)
				ind = IND_REV_RESYNC_NEEDED;
			else
				ind = IND_LOGGING;
		} else if ((rdc_info[rdcindex].flags & RDC_SLAVE) &&
		    (rdc_info[rdcindex].flags & RDC_SYNCING)) {
			if (rdc_info[rdcindex].flags & RDC_PRIMARY)
				ind = IND_RESYNC_REVERSE;
			else
				ind = IND_RESYNC;
		} else if (rdc_info[rdcindex].flags & RDC_SYNCING) {
			if (rdc_info[rdcindex].flags & RDC_PRIMARY)
				ind = IND_RESYNC;
			else
				ind = IND_RESYNC_REVERSE;
		} else
			ind = IND_ENABLED;

		phost = rdc_info[rdcindex].primary.intf;
		pfile = rdc_info[rdcindex].primary.file;
		shost = rdc_info[rdcindex].secondary.intf;
		sfile = rdc_info[rdcindex].secondary.file;

		if ((len = strlen(phost)) > 8) {
			(void) mvprintw(4 + k, 0, ".%+7s:",
				phost + len - 7);
		} else
			(void) mvprintw(4 + k, 0, "%+8s:", phost);

		if ((len = strlen(pfile)) > DISPLEN) {
			(void) mvprintw(4 + k, 9, "...%-13s",
			    pfile + len - DISPLEN + 3);
		} else
			(void) mvprintw(4 + k, 9, "%-16s", pfile);

		(void) attron(A_BOLD);
		(void) mvprintw(4 + k, 26, "*");
		(void) mvprintw(4 + k, 28, "*");

		(void) mvprintw(4 + k, 56, "%-8s", status[ind]);
		(void) attroff(A_BOLD);

		if (ind == IND_RESYNC_REVERSE) {
			if (bright && !(rdc_info[rdcindex].flags & RDC_LOGGING))
				(void) mvprintw(4 + k, 27, "<");
			if (rdc_info[rdcindex].flags & RDC_PRIMARY &&
			    !(rdc_info[rdcindex].flags & RDC_LOGGING))
				calc_completion(rdcindex,
				rdc_info[rdcindex].bits_set, 4 + k);
		} else if (ind == IND_RESYNC) {
			if (bright && !(rdc_info[rdcindex].flags & RDC_LOGGING))
				(void) mvprintw(4 + k, 27, ">");
			if (rdc_info[rdcindex].flags & RDC_PRIMARY &&
			    !(rdc_info[rdcindex].flags & RDC_LOGGING))
				calc_completion(rdcindex,
				rdc_info[rdcindex].bits_set, 4 + k);
		} else if (ind == IND_LOGGING)
			(void) mvprintw(4 + k, 27, ".");
		else if (ind == IND_ENABLED)
			(void) mvprintw(4 + k, 27, "=");

		if ((len = strlen(shost)) > 8) {
			(void) mvprintw(4 + k, 30, ".%+7s:",
				shost + len - 7);
		} else
			(void) mvprintw(4 + k, 30, "%+8s:", shost);

		if ((len = strlen(sfile)) > DISPLEN) {
			(void) mvprintw(4 + k, 39, "...%-13s",
			sfile + len - DISPLEN + 3);
		} else
			(void) mvprintw(4 + k, 39, "%-16s", sfile);

		k++;
	}

	k += 5;
	(void) attron(A_UNDERLINE);
	for (i = 0; i < 80; i++)
		(void) mvprintw(k, i, " ");
	k += 2;
	(void) mvprintw(k,  0, "partition");
	(void) mvprintw(k, 16, "recovery needed");
	(void) mvprintw(k, 48, "recovery completed");
	(void) attroff(A_UNDERLINE);
	k += 2;

	for (rdcindex = 0; rdcindex < rdc_enabled_sets; rdcindex++)  {
		if (!(rdc_info[rdcindex].flags & RDC_ENABLED) ||
		    !dual_on_off[rdcindex])
			continue;

		if (!(rdc_info[rdcindex].flags & RDC_PRIMARY)) {
			continue;
		}
		if (!(rdc_info[rdcindex].flags & RDC_SLAVE) &&
		    !(rdc_info[rdcindex].flags & RDC_SYNCING) &&
		    !(rdc_info[rdcindex].flags & RDC_LOGGING)) {
			continue;
		}

		len = strlen(rdc_info[rdcindex].secondary.file);
		if (len > 15) {
			strcpy(fn, "...");
			strcat(fn,
			    rdc_info[rdcindex].secondary.file + len - 12);
		} else
			strcpy(fn, rdc_info[rdcindex].secondary.file);
		(void) mvprintw(k, 0, "%-15s", fn);

		segs = FBA_TO_LOG_LEN(rdc_info[rdcindex].volume_size);
		pct  = segs ?
		    ((float)rdc_info[rdcindex].bits_set / (float)segs) : 0.0;
		stars = (int)(pct * 20.0);
		while (stars > 0) {
			(void) mvprintw(k, 16 + stars, "*");
			stars--;
		}
		(void) attron(A_BOLD);
		(void) mvprintw(k, 16, "[");
		(void) mvprintw(k, 37, "]");
		(void) attroff(A_BOLD);
		(void) mvprintw(k, 39, "%6.2f%%", pct * 100.0);

		if (rdc_info[rdcindex].flags & RDC_SYNCING)
			pct = ((float)rdc_info[rdcindex].sync_pos /
			    (float)rdc_info[rdcindex].volume_size);
		else
			pct = 0.0;
		stars = (int)(pct * 20.0);
		while (stars > 0) {
			(void) mvprintw(k, 48 + stars, "*");
			stars--;
		}
		(void) attron(A_BOLD);
		(void) mvprintw(k, 48, "[");
		(void) mvprintw(k, 69, "]");
		(void) attroff(A_BOLD);
		(void) mvprintw(k, 70, "%6.2f%%", pct * 100.0);
		k++;
	}
	bright = !bright;
	return (0);
}

/*
 * Calculate a time interval in milliseconds using the
 * micosecond counter
 */
void
calc_time(void)
{
	unsigned int cur;

	cur = USEC_READ();
	dc_delta_time = cur > dc_prev_time ? cur - dc_prev_time :
		cur + 0xFFFFFFFF - dc_prev_time;
	dc_delta_time /= 1000;
	dc_prev_time = cur;
}

/*
 * Calculate estimated time of completion of resync
 */
void
calc_completion(int cd, int updates_left, int l)
{
	int delta_done;
	double rate;
	long time_left;
	long hours;
	long minutes;
	static int initted = 0;

	if (!initted) {
		updates_prev[cd] = updates_left;
		initted = 1;
		return;
	}

	/*
	 * Caclulate updates since last check
	 */
	delta_done = updates_prev[cd] - updates_left;
	updates_prev[cd] = updates_left;

	/*
	 * If no updates, don't bother estimating completion time
	 */
	if (delta_done <= 0) {
		samples[cd] = 0;
		return;
	}

	rate = delta_done * 1000.0 / dc_delta_time;

	/*
	 * Calculate rate of updates as a weighted average
	 * of previous and current rate
	 */
	if (rate_prev[cd] && samples[cd] > SAMPLE_RATE)
		rate = (rate_prev[cd] * 4.0 + rate) / 5.0;
	rate_prev[cd] = rate;
	samples[cd]++;

	/*
	 * Get enough samples before making estimate
	 */
	if (samples[cd]++ < SAMPLE_RATE)
		return;

	time_left = (long)(updates_left/rate);   /* time left in seconds */

	if (time_left < 0)
		return;

	hours = time_left / (60 * 60);
	time_left -= hours * (60 * 60);
	minutes = time_left / 60;
	time_left -= minutes * 60;
	(void) mvprintw(l, 67,
	    "time %02d:%02d:%02d  \n", hours, minutes, time_left);
}

void
disp_total_stats(void)
{
	unsigned int	read_s, write_s, access_s;
	double readp, writep;
	unsigned int	rmiss_s, wmiss_s;
	double  kbps = 2.0;
	int	rtotal, wtotal, i, j;
	unsigned int throughput = 0, rthroughput = 0, creads = 0, cwrites = 0;
	char	status_bit, down = 0;
	int	len;
	char	fn[19];

	read_s  = cs_cur->st_rdhits;
	write_s = cs_cur->st_wrhits;
	rmiss_s = cs_cur->st_rdmiss;
	wmiss_s = cs_cur->st_wrmiss;
	access_s = (read_s + write_s + rmiss_s + wmiss_s);

	rtotal = cs_cur->st_rdhits + cs_cur->st_rdmiss;
	wtotal = cs_cur->st_wrhits + cs_cur->st_wrmiss;
	if (rtotal != 0)
		readp = cs_cur->st_rdhits / (double)rtotal;
	else
		readp = 0.0;

	if (wtotal != 0)
		writep = cs_cur->st_wrhits / (double)wtotal;
	else
		writep = 0.0;

	set_on_off();
	(void) mvprintw(0, 14,
	    "******     Storage Cache (Cumulative)      ******");
	(void) mvprintw(2, 30, "disk_io                  cache");
	(void) attron(A_UNDERLINE);
	(void) mvprintw(3,  1,
	    " cd cached_partition      reads     writes      reads     writes");
	(void) attroff(A_UNDERLINE);
	for (i = 0, j = 0; j < cs_cur->st_count; i++) {
		if (i >= sdbc_max_devices)
			break;
		if (cs_cur->st_shared[i].sh_alloc)  {
			cs_cur->st_shared[i].sh_disk_write /= kbps;
			cs_cur->st_shared[i].sh_disk_read /= kbps;
			cs_cur->st_shared[i].sh_cache_write /= kbps;
			cs_cur->st_shared[i].sh_cache_read /= kbps;
			rthroughput += cs_cur->st_shared[i].sh_disk_read;
			throughput += cs_cur->st_shared[i].sh_disk_write;
			creads += cs_cur->st_shared[i].sh_cache_read;
			cwrites += cs_cur->st_shared[i].sh_cache_write;
			if (!down)
				down = cs_cur->st_shared[i].sh_failed;
			if (cs_cur->st_shared[i].sh_failed && bright)
				status_bit = '*';
			else
				status_bit = ' ';
			if ((len =
			    strlen(cs_cur->st_shared[i].sh_filename)) > 15) {
				strcpy(fn, "...");
				strcat(fn, cs_cur->st_shared[i].sh_filename +
				    len - 12);
			} else
				strcpy(fn, cs_cur->st_shared[i].sh_filename);

			if (on_off[i]) {
				(void) mvprintw(4 + j, 1,
				    "%3d %-15s%c %10u %10u %10u %10u",
				    cs_cur->st_shared[i].sh_cd,
				    fn,
				    status_bit,
				    cs_cur->st_shared[i].sh_disk_read,
				    cs_cur->st_shared[i].sh_disk_write,
				    cs_cur->st_shared[i].sh_cache_read,
				    cs_cur->st_shared[i].sh_cache_write);
				j++;
			}
		}
	}
	bright = !bright;

	(void) mvprintw(4 + j, 22,
	    "---------- ---------- ---------- ----------");
	(void) mvprintw(5 + j, 8, " Kbytes total:%10u %10u %10u %10u",
	    (int)rthroughput, (int)throughput,
	    (int)creads, (int)cwrites);
	(void) mvprintw(7 + j, 1, " accesses");
	(void) mvprintw(7 + j, 18, "read        write    %%readh  %%writeh");

	(void) attron(A_UNDERLINE);
	(void) mvprintw(8 + j, 1, "            ");
	(void) mvprintw(8 + j, 13,
	    "                                                ");
	(void) mvprintw(8 + j, 11, "(    misses) (    misses)");
	(void) attroff(A_UNDERLINE);

	(void) mvprintw(9 + j, 0, "%10u  %10u   %10u    %6.1f   %6.1f",
	    access_s, read_s, write_s, readp*100.0, writep*100.0);
	(void) mvprintw(10 + j, 0,
	    "           (%10u) (%10u)\n\n", rmiss_s, wmiss_s);

	(void) attron(A_UNDERLINE);
	(void) mvprintw(13 + j, 1, "cachesize  blocksize");
	(void) attroff(A_UNDERLINE);
	(void) mvprintw(14 + j, 1, "%8dK %10d", cs_cur->st_cachesize / 1024,
	    cs_cur->st_blksize);

	(void) attron(A_UNDERLINE);
	(void) mvprintw(16 + j, 1, "Write blocks available:");
	(void) attroff(A_UNDERLINE);
	(void) mvprintw(17 + j, 1, "Net 0: %6d", cs_cur->st_wlru_inq);

	(void) attron(A_UNDERLINE);
	(void) mvprintw(19 + j, 1, "LRU stats:  Blocks	Requeued    Optimized");
	(void) attroff(A_UNDERLINE);
	(void) mvprintw(20 + j, 7, "%12d %12u %12u", cs_cur->st_lru_blocks,
	    cs_cur->st_lru_req, cs_cur->st_lru_noreq);

	if (down)
		(void) mvprintw(25 + j, 1, "* -- disk off-line");
}
