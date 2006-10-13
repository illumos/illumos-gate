/***************************************************************************
 * CVSID: $Id: hal-storage-mount.c,v 1.7 2006/06/21 00:44:03 david Exp $
 *
 * hal-storage-cleanup-mountpoint.c : Cleanup mount point when hald detects
 * that an unmount not done through Unmount()
 *
 * Copyright (C) 2006 David Zeuthen, <david@fubar.dk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <glib/gstdio.h>

#include "hal-storage-shared.h"

/*#define DEBUG*/
#define DEBUG

static void
usage (void)
{
	fprintf (stderr, "This program should only be started by hald.\n");
	exit (1);
}

static void
do_cleanup (const char *mount_point)
{
	int i, j;
	FILE *hal_mtab_orig;
	int hal_mtab_orig_len;
	int num_read;
	char *hal_mtab_buf;
	char **lines;
	FILE *hal_mtab_new;
	gboolean found;

	hal_mtab_orig = fopen ("/media/.hal-mtab", "r");
	if (hal_mtab_orig == NULL) {
		unknown_error ("Cannot open /media/.hal-mtab");
	}
	if (fseek (hal_mtab_orig, 0L, SEEK_END) != 0) {
		unknown_error ("Cannot seek to end of /media/.hal-mtab");
	}
	hal_mtab_orig_len = ftell (hal_mtab_orig);
	if (hal_mtab_orig_len < 0) {
		unknown_error ("Cannot determine size of /media/.hal-mtab");
	}
	rewind (hal_mtab_orig);
	hal_mtab_buf = g_new0 (char, hal_mtab_orig_len + 1);
	num_read = fread (hal_mtab_buf, 1, hal_mtab_orig_len, hal_mtab_orig);
	if (num_read != hal_mtab_orig_len) {
		unknown_error ("Cannot read from /media/.hal-mtab");
	}
	fclose (hal_mtab_orig);

#ifdef DEBUG
	printf ("hal_mtab = '%s'\n", hal_mtab_buf);
#endif

	lines = g_strsplit (hal_mtab_buf, "\n", 0);
	g_free (hal_mtab_buf);

	/* find the entry we're going to unmount */
	found = FALSE;
	for (i = 0; lines[i] != NULL && !found; i++) {
		char **line_elements;

#ifdef DEBUG
		printf (" line = '%s'\n", lines[i]);
#endif

		if ((lines[i])[0] == '#')
			continue;

		line_elements = g_strsplit (lines[i], "\t", 6);
		if (g_strv_length (line_elements) == 6) {

#ifdef DEBUG
			printf ("  devfile     = '%s'\n", line_elements[0]);
			printf ("  uid         = '%s'\n", line_elements[1]);
			printf ("  session id  = '%s'\n", line_elements[2]);
			printf ("  fs          = '%s'\n", line_elements[3]);
			printf ("  options     = '%s'\n", line_elements[4]);
			printf ("  mount_point = '%s'\n", line_elements[5]);
#endif

			if (strcmp (line_elements[5], mount_point) == 0) {
				char *line_to_free;

				found = TRUE;

				line_to_free = lines[i];
				for (j = i; lines[j] != NULL; j++) {
					lines[j] = lines[j+1];
				}
				lines[j] = NULL;
				g_free (line_to_free);
			}
		}

		g_strfreev (line_elements);
	}

	if (!found) {
		unknown_error ("mount point is not /media/.hal-mtab");
	}

#ifdef DEBUG
	printf ("Found entry for mount point '%s' in /media/.hal-mtab", mount_point);
#endif

	/* create new .hal-mtab~ file without the entry we're going to unmount */
	hal_mtab_new = fopen ("/media/.hal-mtab~", "w");
	if (hal_mtab_new == NULL) {
		unknown_error ("Cannot create /media/.hal-mtab~");
	}
	for (i = 0; lines[i] != NULL; i++) {
		if (i > 0) {
			char anewl[2] = "\n\0";
			if (fwrite (anewl, 1, 1, hal_mtab_new) != 1) {
				unknown_error ("Cannot write to /media/.hal-mtab~");
			}
		}

		if (fwrite (lines[i], 1, strlen (lines[i]), hal_mtab_new) != strlen (lines[i])) {
			unknown_error ("Cannot write to /media/.hal-mtab~");
		}

	}
	fclose (hal_mtab_new);

	g_strfreev (lines);

	/* remove directory */
	if (g_rmdir (mount_point) != 0) {
		unlink ("/media/.hal-mtab~");
		unknown_error ("Cannot remove directory");
	}

	/* set new .hal-mtab file */
	if (rename ("/media/.hal-mtab~", "/media/.hal-mtab") != 0) {
		unlink ("/media/.hal-mtab~");
		unknown_error ("Cannot rename /media/.hal-mtab~ to /media/.hal-mtab");
	}

}

int
main (int argc, char *argv[])
{
	char *mount_point;

	if (!lock_hal_mtab ()) {
		unknown_error ("Cannot obtain lock on /media/.hal-mtab");
	}

	mount_point = getenv ("HALD_CLEANUP");
	if (mount_point == NULL)
		usage ();

#ifdef DEBUG
	printf ("in hal-storage-cleanup-mountpoint for mount point '%s'\n", mount_point);
#endif
	do_cleanup (mount_point);


	unlock_hal_mtab ();
	return 0;
}
