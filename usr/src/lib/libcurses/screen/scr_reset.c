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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*LINTLIBRARY*/

#include	"curses_inc.h"
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<stdlib.h>

/*
 * Initialize the screen image to be the image contained
 * in the given file. This is usually used in a child process
 * to initialize its idea of the screen image to be that of its
 * parent.
 *
 * filep:	pointer to the output stream
 * type:	0: <curses> should assume that the physical screen is
 *		   EXACTLY as stored in the file. Therefore, we take
 *		   special care to make sure that /dev/tty and the terminal
 *		   did not change in any way.  This information can then
 *		   be used in the update optimization of the new program
 *		   so that the screen does not have to be cleared.  Instead,
 *		   curses, by knowing what's on the screen can optimally
 *		   update it with the information of the new program.
 *
 *		1: Tell <curses> that the stored image should be
 *		   the physical image.  Sort of like a huge waddstr onto
 *		   curscr.  This can be used when a library wants to save
 *		   a screen image and restore it at a later time.
 *
 *		2: Tell <curses> that the stored image is the physical
 *		   image and also it is what the new program wants on the
 *		   screen.  This can be be thought of as a screen inheritance
 *		   function.
 */

int
scr_reset(FILE *filep, int type)
{
	WINDOW		*win = NULL, *win1 = NULL;
	int		*hash, y;
	char		clearit = FALSE;
	short		magic;
	struct	stat	statbuf;
	time_t		ttytime;

	if (type != 1 && exit_ca_mode && *exit_ca_mode && non_rev_rmcup) {
		if (type == 0)
			goto err;
		else {
#ifdef	DEBUG
			if (outf)
				fprintf(outf, "clear it because of "
				    "exit_ca_mode\n");
#endif	/* DEBUG */
			clearit = TRUE;
		}
	}

	/* check magic number */
	if (fread((char *)&magic, sizeof (short), 1, filep) != 1)
		goto err;
	if (magic != SVR3_DUMP_MAGIC_NUMBER)
		goto err;

	/* get modification time of image in file */
	if (fread((char *)&ttytime, sizeof (time_t), 1, filep) != 1)
		goto err;

	if ((type != 1) && ((ttyname(cur_term->Filedes) == NULL) ||
	    (fstat(cur_term->Filedes, &statbuf) < 0) ||
	    (statbuf.st_mtime != ttytime))) {
		if (type == 0)
			goto err;
		else {
#ifdef	DEBUG
			if (outf)
				fprintf(outf, "Filedes = %hd, "
				    "statbuf.st_mtime = %d, "
				    "ttytime = %d\n", cur_term->Filedes,
				    statbuf.st_mtime, ttytime);
#endif	/* DEBUG */
			clearit = TRUE;
		}
	}

	/* if get here, everything is ok, read the curscr image */
	if (((win = getwin(filep)) == NULL) ||
	    ((type == 2) && ((win1 = dupwin(win)) == NULL)) ||
	    (win->_maxy != curscr->_maxy) || (win->_maxx != curscr->_maxx) ||
	    /* soft labels */
	    (fread((char *)&magic, sizeof (int), 1, filep) != 1))
		goto err;

	/*
	 * if soft labels were dumped, we would like either read them
	 * or advance the file pointer pass them
	 */
	if (magic) {
		short	i, labmax, lablen;
		SLK_MAP	*slk = SP->slk;
		/*
		 * Why doesn't the following line and the two below
		 * that access those variables work ?
		 */
		/*
		 * char	**labdis = SP->slk->_ldis, **labval = SP->slk->_lval;
		 */

		if ((fread((char *)&labmax, sizeof (short), 1, filep) != 1) ||
		    (fread((char *)&lablen, sizeof (short), 1, filep) != 1)) {
			goto err;
		}

		if (slk != NULL) {
			if ((labmax != slk->_num) ||
			    (lablen != (slk->_len + 1)))
				goto err;

			for (i = 0; i < labmax; i++) {
				/*
				 * if ((fread(labdis[i], sizeof (char), lablen,
				 * filep) != lablen) ||
				 * (fread(labval[i], sizeof (char), lablen,
				 * filep != lablen))
				 */
				if ((fread(slk->_ldis[i], sizeof (char),
				    lablen, filep) != lablen) ||
				    (fread(slk->_lval[i],
				    sizeof (char), lablen, filep) != lablen)) {
					goto err;
				}
			}
			(*_do_slk_tch)();
		} else {
			if (fseek(filep, (long)(2 * labmax * lablen *
			    sizeof (char)), 1) != 0)
				goto err;
		}
	}

	/* read the color information(if any) from the file 		*/

	if (fread((char *)&magic, sizeof (int), 1, filep) != 1)
		goto err;

	if (magic) {
		int  colors, color_pairs;
		bool could_change;
		int i;

	/* if the new terminal doesn't support colors, or it supports    */
	/* less colors (or color_pairs) than the old terminal, or	 */
	/* start_color() has not been called, simply advance  the file	 */
	/* pointer pass the color related info.				 */
	/* Note: must to read the first line of color info, even if the  */
	/* new terminal doesn't support color, in order to know how to   */
	/* deal with the rest of the file				 */

		if ((fread((char *)&colors, sizeof (int), 1, filep) != 1) ||
		    (fread((char *)&color_pairs, sizeof (int), 1,
		    filep) != 1) || (fread((char *)&could_change,
		    sizeof (char), 1, filep) != 1))
			goto err;

		if (max_pairs == -1 || cur_term->_pairs_tbl == NULL ||
		    colors > max_colors || color_pairs > max_pairs) {
			if (fseek(filep, (long)(colors * sizeof (_Color) +
			    color_pairs * sizeof (_Color_pair)), 1) != 0)
				goto err;
		} else {
			_Color_pair *ptp, *save_ptp;

	    /* if both old and new terminals could modify colors, read in */
	    /* color table, and call init_color for each color		  */

			if (could_change) {
				if (can_change) {
					_Color	 *ctp, *save_ctp;

					if ((save_ctp = (ctp = (_Color *)
					    malloc(colors *
					    sizeof (_Color)))) == NULL)
						goto err;

					if (fread(ctp, sizeof (_Color),
					    colors, filep) != colors)
						goto err;

					for (i = 0; i < colors; i++, ctp++) {
						/* LINTED */
						(void) init_color((short)i,
						    ctp->r, ctp->g, ctp->b);
					}
					free(save_ctp);
				} else {

		/* the old terminal could modify colors, by the new one */
		/* cannot skip over color_table info.			*/

					if (fseek(filep, (long)(colors *
					    sizeof (_Color)), 1) != 0)
						goto err;
				}
			}

	    /* read color_pairs info. call init_pair for each pair	*/

			if ((save_ptp = (ptp = (_Color_pair *)
			    malloc(color_pairs * sizeof (_Color_pair)))) ==
			    NULL)
				goto err;
			if (fread(ptp, sizeof (_Color_pair), color_pairs,
			    filep) != color_pairs) {
err:
				if (win != NULL)
					(void) delwin(win);
				if (win1 != NULL)
					(void) delwin(win1);
				if (type == 0)
					curscr->_clear = TRUE;
				return (ERR);
			}

			for (i = 1, ++ptp; i <= color_pairs; i++, ptp++) {
				if (ptp->init)
					/* LINTED */
					(void) init_pair((short)i,
					    ptp->foreground, ptp->background);
			}
			free(save_ptp);
		}
	}

	/* substitute read in window for the curscr */
	switch (type) {
		case 1:
		case 2:
			(void) delwin(_virtscr);
			hash = _VIRTHASH;
			if (type == 1) {
				SP->virt_scr = _virtscr = win;
				_VIRTTOP = 0;
				_VIRTBOT = curscr->_maxy - 1;
				break;
			}
			SP->virt_scr = _virtscr = win1;
			_VIRTTOP = curscr->_maxy;
			_VIRTBOT = -1;
			/* clear the hash table */
			for (y = curscr->_maxy; y > 0; --y)
				*hash++ = _NOHASH;
			/* FALLTHROUGH */
		case 0:
			{
			int	saveflag = curscr->_flags & _CANT_BE_IMMED;

			(void) delwin(curscr);
			SP->cur_scr = curscr = win;
			curscr->_sync = TRUE;
			curscr->_flags |= saveflag;
			hash = _CURHASH;
		}
	}

	/* clear the hash table */
	for (y = curscr->_maxy; y > 0; --y)
		*hash++ = _NOHASH;

	curscr->_clear = clearit;
	return (OK);
}
