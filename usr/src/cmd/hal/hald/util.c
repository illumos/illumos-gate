/***************************************************************************
 * CVSID: $Id$
 *
 * util.c - Various utilities
 *
 * Copyright (C) 2004 David Zeuthen, <david@fubar.dk>
 *
 * Licensed under the Academic Free License version 2.1
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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/file.h>
#include <sys/hexdump.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#include "osspec.h"
#include "logger.h"
#include "hald.h"
#include "hald_runner.h"
#include "hald_dbus.h"
#include "device_info.h"

#include "util.h"

/** Determine whether the given character is valid as the first character
 *  in a name.
 */
#define VALID_INITIAL_NAME_CHARACTER(c)          \
	(((c) >= 'A' && (c) <= 'Z') ||           \
	((c) >= 'a' && (c) <= 'z') ||            \
	((c) == '_'))

/** Determine whether the given character is valid as a second or later
 *  character in a name.
 */
#define VALID_NAME_CHARACTER(c)                  \
	(((c) >= '0' && (c) <= '9') ||           \
	((c) >= 'A' && (c) <= 'Z') ||            \
	((c) >= 'a' && (c) <= 'z') ||            \
	((c) == '_'))

gboolean
hal_util_remove_trailing_slash (gchar *path)
{
	gchar *c = NULL;

	if (path == NULL) {
		return FALSE;
	}

	c = strrchr (path, '/');
	if (c == NULL) {
		HAL_WARNING (("Invalid path %s", path));
		return 1;
	}
	if (*(c+1) == '\0')
		*c = '\0';

	return TRUE;
}

/** Given a path, /foo/bar/bat/foobar, return the last element, e.g.
 *  foobar.
 *
 *  @param  path                Path
 *  @return                     Pointer into given string
 */
const gchar *
hal_util_get_last_element (const gchar *s)
{
	int len;
	const gchar *p;

	len = strlen (s);
	for (p = s + len - 1; p > s; --p) {
		if ((*p) == '/')
			return p + 1;
	}

	return s;
}

/** Given a path, this functions finds the path representing the
 *  parent directory by truncation.
 *
 *  @param  path                Path
 *  @return                     Path for parent or NULL. Must be freed by caller
 */
gchar *
hal_util_get_parent_path (const gchar *path)
{
	guint i;
	guint len;
	gchar *parent_path;

	/* Find parent device by truncating our own path */
	parent_path = g_strndup (path, HAL_PATH_MAX);
	len = strlen (parent_path);
	for (i = len - 1; parent_path[i] != '/'; --i) {
		parent_path[i] = '\0';
	}
	parent_path[i] = '\0';

	return parent_path;
}

gchar *
hal_util_get_normalized_path (const gchar *path1, const gchar *path2)
{
	int len1;
	int len2;
	const gchar *p1;
	const gchar *p2;
	gchar buf[HAL_PATH_MAX];

	len1 = strlen (path1);
	len2 = strlen (path2);

	p1 = path1 + len1;

	p2 = path2;
	while (p2 < path2 + len2 && strncmp (p2, "../", 3) == 0) {
		p2 += 3;

		while (p1 >= path1 && *(--p1)!='/')
			;
	}

	if ((p1-path1) < 0) {
		HAL_ERROR (("Could not normalize '%s' and '%s', return 'NULL'", path1, path2));
		return NULL;
	}

	strncpy (buf, path1, (p1-path1));
	buf[p1-path1] = '\0';

	return g_strdup_printf ("%s/%s", buf, p2);
}

gboolean
hal_util_get_int_from_file (const gchar *directory, const gchar *file, gint *result, gint base)
{
	FILE *f;
	char buf[64];
	gchar path[HAL_PATH_MAX];
	gboolean ret;

	f = NULL;
	ret = FALSE;

	g_snprintf (path, sizeof (path), "%s/%s", directory, file);

	f = fopen (path, "rb");
	if (f == NULL) {
		HAL_ERROR (("Cannot open '%s'", path));
		goto out;
	}

	if (fgets (buf, sizeof (buf), f) == NULL) {
		HAL_ERROR (("Cannot read from '%s'", path));
		goto out;
	}

	/* TODO: handle error condition */
	*result = strtol (buf, NULL, base);
	ret = TRUE;

out:
	if (f != NULL)
		fclose (f);

	return ret;
}

gboolean
hal_util_set_int_from_file (HalDevice *d, const gchar *key, const gchar *directory, const gchar *file, gint base)
{
	gint value;
	gboolean ret;

	ret = FALSE;

	if (hal_util_get_int_from_file (directory, file, &value, base))
		ret = hal_device_property_set_int (d, key, value);

	return ret;
}


gboolean
hal_util_get_uint64_from_file (const gchar *directory, const gchar *file, guint64 *result, gint base)
{
	FILE *f;
	char buf[64];
	gchar path[HAL_PATH_MAX];
	gboolean ret;

	f = NULL;
	ret = FALSE;

	g_snprintf (path, sizeof (path), "%s/%s", directory, file);

	f = fopen (path, "rb");
	if (f == NULL) {
		HAL_ERROR (("Cannot open '%s'", path));
		goto out;
	}

	if (fgets (buf, sizeof (buf), f) == NULL) {
		HAL_ERROR (("Cannot read from '%s'", path));
		goto out;
	}

	/* TODO: handle error condition */
	*result = strtoll (buf, NULL, base);

	ret = TRUE;

out:
	if (f != NULL)
		fclose (f);

	return ret;
}

gboolean
hal_util_set_uint64_from_file (HalDevice *d, const gchar *key, const gchar *directory, const gchar *file, gint base)
{
	guint64 value;
	gboolean ret;

	ret = FALSE;

	if (hal_util_get_uint64_from_file (directory, file, &value, base))
		ret = hal_device_property_set_uint64 (d, key, value);

	return ret;
}

gboolean
hal_util_get_bcd2_from_file (const gchar *directory, const gchar *file, gint *result)
{
	FILE *f;
	char buf[64];
	gchar path[HAL_PATH_MAX];
	gboolean ret;
	gint digit;
	gint left, right;
	gboolean passed_white_space;
	gint num_prec;
	gsize len;
	gchar c;
	guint i;

	f = NULL;
	ret = FALSE;

	g_snprintf (path, sizeof (path), "%s/%s", directory, file);

	f = fopen (path, "rb");
	if (f == NULL) {
		HAL_ERROR (("Cannot open '%s'", path));
		goto out;
	}

	if (fgets (buf, sizeof (buf), f) == NULL) {
		HAL_ERROR (("Cannot read from '%s'", path));
		goto out;
	}

	left = 0;
	len = strlen (buf);
	passed_white_space = FALSE;
	for (i = 0; i < len && buf[i] != '.'; i++) {
		if (g_ascii_isspace (buf[i])) {
			if (passed_white_space)
				break;
			else
				continue;
		}
		passed_white_space = TRUE;
		left *= 16;
		c = buf[i];
		digit = (int) (c - '0');
		left += digit;
	}
	i++;
	right = 0;
	num_prec = 0;
	for (; i < len; i++) {
		if (g_ascii_isspace (buf[i]))
			break;
		if (num_prec == 2)	        /* Only care about two digits
						 * of precision */
			break;
		right *= 16;
		c = buf[i];
		digit = (int) (c - '0');
		right += digit;
		num_prec++;
	}

	for (; num_prec < 2; num_prec++)
		right *= 16;

	*result = left * 256 + (right & 255);
	ret = TRUE;

out:
	if (f != NULL)
		fclose (f);

	return ret;
}

gboolean
hal_util_set_bcd2_from_file (HalDevice *d, const gchar *key, const gchar *directory, const gchar *file)
{
	gint value;
	gboolean ret;

	ret = FALSE;

	if (hal_util_get_bcd2_from_file (directory, file, &value))
		ret = hal_device_property_set_int (d, key, value);

	return ret;
}

gchar *
hal_util_get_string_from_file (const gchar *directory, const gchar *file)
{
	FILE *f;
	static gchar buf[256];
	gchar path[HAL_PATH_MAX];
	gchar *result;
	gsize len;
	gint i;

	f = NULL;
	result = NULL;

	g_snprintf (path, sizeof (path), "%s/%s", directory, file);

	f = fopen (path, "rb");
	if (f == NULL) {
		HAL_ERROR (("Cannot open '%s'", path));
		goto out;
	}

	buf[0] = '\0';
	if (fgets (buf, sizeof (buf), f) == NULL) {
		HAL_ERROR (("Cannot read from '%s'", path));
		goto out;
	}

	len = strlen (buf);
	if (len>0)
		buf[len-1] = '\0';

	/* Clear remaining whitespace */
	for (i = len - 2; i >= 0; --i) {
		if (!g_ascii_isspace (buf[i]))
			break;
		buf[i] = '\0';
	}

	result = buf;

out:
	if (f != NULL)
		fclose (f);

	return result;
}

gboolean
hal_util_set_string_from_file (HalDevice *d, const gchar *key, const gchar *directory, const gchar *file)
{
	gchar *buf;
	gboolean ret;

	ret = FALSE;

	if ((buf = hal_util_get_string_from_file (directory, file)) != NULL)
		ret = hal_device_property_set_string (d, key, buf);

	return ret;
}

void
hal_util_compute_udi (HalDeviceStore *store, gchar *dst, gsize dstsize, const gchar *format, ...)
{
	guint i;
	va_list args;
	gchar buf[256];

	va_start (args, format);
	g_vsnprintf (buf, sizeof (buf), format, args);
	va_end (args);

	g_strcanon (buf,
		    "/_"
		    "abcdefghijklmnopqrstuvwxyz"
		    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		    "1234567890", '_');

	g_strlcpy (dst, buf, dstsize);
	if (hal_device_store_find (store, dst) == NULL)
		goto out;

	for (i = 0; ; i++) {
		g_snprintf (dst, dstsize, "%s_%d", buf, i);
		if (hal_device_store_find (store, dst) == NULL)
			goto out;
	}

out:
	;
}


gboolean
hal_util_path_ascend (gchar *path)
{
	gchar *p;

	if (path == NULL)
		return FALSE;

	p = strrchr (path, '/');
	if (p == NULL)
		return FALSE;

	*p = '\0';
	return TRUE;
}

static gboolean _grep_can_reuse = FALSE;

void
hal_util_grep_discard_existing_data (void)
{
	_grep_can_reuse = FALSE;
}

/** Given a directory and filename, open the file and search for the
 *  first line that starts with the given linestart string. Returns
 *  the rest of the line as a string if found.
 *
 *  @param  directory           Directory, e.g. "/proc/acpi/battery/BAT0"
 *  @param  file                File, e.g. "info"
 *  @param  linestart           Start of line, e.g. "serial number"
 *  @param  reuse               Whether we should reuse the file contents
 *                              if the file is the same; can be cleared
 *                              with hal_util_grep_discard_existing_data()
 *  @return                     NULL if not found, otherwise the remainder
 *                              of the line, e.g. ":           21805" if
 *                              the file /proc/acpi/battery/BAT0 contains
 *                              this line "serial number:           21805"
 *                              The string is only valid until the next
 *                              invocation of this function.
 */
gchar *
hal_util_grep_file (const gchar *directory, const gchar *file, const gchar *linestart, gboolean reuse)
{
	static gchar buf[2048];
	static unsigned int bufsize;
	static gchar filename[HAL_PATH_MAX];
	static gchar oldfilename[HAL_PATH_MAX];
	gchar *result;
	gsize linestart_len;
	gchar *p;

	result = NULL;

	/* TODO: use reuse and _grep_can_reuse parameters to avoid loading
	 *       the file again and again
	 */

	if (file != NULL && strlen (file) > 0)
		snprintf (filename, sizeof (filename), "%s/%s", directory, file);
	else
		strncpy (filename, directory, sizeof (filename));

	if (_grep_can_reuse && reuse && strcmp (oldfilename, filename) == 0) {
		/* just reuse old file; e.g. bufsize, buf */
		/*HAL_INFO (("hal_util_grep_file: reusing buf for %s", filename));*/
	} else {
		FILE *f;

		f = fopen (filename, "r");
		if (f == NULL)
			goto out;
		bufsize = fread (buf, sizeof (char), sizeof (buf) - 1, f);
		buf[bufsize] = '\0';
		fclose (f);

		/*HAL_INFO (("hal_util_grep_file: read %s of %d bytes", filename, bufsize));*/
	}

	/* book keeping */
	_grep_can_reuse = TRUE;
	strncpy (oldfilename, filename, sizeof(oldfilename));

	linestart_len = strlen (linestart);

	/* analyze buf */
	p = buf;
	do {
		unsigned int linelen;
		static char line[256];

		for (linelen = 0; p[linelen] != '\n' && p[linelen] != '\0'; linelen++)
			;

		if (linelen < sizeof (line)) {

			strncpy (line, p, linelen);
			line[linelen] = '\0';

			if (strncmp (line, linestart, linestart_len) == 0) {
				result = line + linestart_len;
				goto out;
			}
		}

		p += linelen + 1;

	} while (p < buf + bufsize);

out:
	return result;
}

gchar *
hal_util_grep_string_elem_from_file (const gchar *directory, const gchar *file,
				     const gchar *linestart, guint elem, gboolean reuse)
{
	gchar *line;
	gchar *res;
	static gchar buf[256];
	gchar **tokens;
	guint i, j;

	res = NULL;
	tokens = NULL;

	if (((line = hal_util_grep_file (directory, file, linestart, reuse)) == NULL) || (strlen (line) == 0))
		goto out;

	tokens = g_strsplit_set (line, " \t:", 0);
	for (i = 0, j = 0; tokens[i] != NULL; i++) {
		if (strlen (tokens[i]) == 0)
			continue;
		if (j == elem) {
			strncpy (buf, tokens[i], sizeof (buf));
			res = buf;
			goto out;
		}
		j++;
	}

out:
	if (tokens != NULL)
		g_strfreev (tokens);

	return res;
}

gint
hal_util_grep_int_elem_from_file (const gchar *directory, const gchar *file,
				  const gchar *linestart, guint elem, guint base, gboolean reuse)
{
	gchar *endptr;
	gchar *strvalue;
	int value;

	value = G_MAXINT;

	strvalue = hal_util_grep_string_elem_from_file (directory, file, linestart, elem, reuse);
	if (strvalue == NULL)
		goto out;

	value = strtol (strvalue, &endptr, base);
	if (endptr == strvalue) {
		value = G_MAXINT;
		goto out;
	}

out:
	return value;
}

/** Get a string value from a formatted text file and assign it to
 *  a property on a device object.
 *
 *  Example: Given that the file /proc/acpi/battery/BAT0/info contains
 *  the line
 *
 *    "design voltage:          10800 mV"
 *
 *  then hal_util_set_string_elem_from_file (d, "battery.foo",
 *  "/proc/acpi/battery/BAT0", "info", "design voltage", 1) will assign
 *  the string "mV" to the property "battery.foo" on d.
 *
 *  @param  d                   Device object
 *  @param  key                 Property name
 *  @param  directory           Directory, e.g. "/proc/acpi/battery/BAT0"
 *  @param  file                File, e.g. "info"
 *  @param  linestart           Start of line, e.g. "design voltage"
 *  @param  elem                Element number after linestart to extract
 *                              excluding whitespace and ':' characters.
 *  @return                     TRUE, if, and only if, the value could be
 *                              extracted and the property was set
 */
gboolean
hal_util_set_string_elem_from_file (HalDevice *d, const gchar *key,
				    const gchar *directory, const gchar *file,
				    const gchar *linestart, guint elem, gboolean reuse)
{
	gboolean res;
	gchar *value;

	res = FALSE;

	if ((value = hal_util_grep_string_elem_from_file (directory, file, linestart, elem, reuse)) == NULL)
		goto out;

	res = hal_device_property_set_string (d, key, value);
out:
	return res;
}

/** Get an integer value from a formatted text file and assign it to
 *  a property on a device object.
 *
 *  Example: Given that the file /proc/acpi/battery/BAT0/info contains
 *  the line
 *
 *    "design voltage:          10800 mV"
 *
 *  then hal_util_set_int_elem_from_file (d, "battery.foo",
 *  "/proc/acpi/battery/BAT0", "info", "design voltage", 0) will assign
 *  the integer 10800 to the property "battery.foo" on d.
 *
 *  @param  d                   Device object
 *  @param  key                 Property name
 *  @param  directory           Directory, e.g. "/proc/acpi/battery/BAT0"
 *  @param  file                File, e.g. "info"
 *  @param  linestart           Start of line, e.g. "design voltage"
 *  @param  elem                Element number after linestart to extract
 *                              excluding whitespace and ':' characters.
 *  @return                     TRUE, if, and only if, the value could be
 *                              extracted and the property was set
 */
gboolean
hal_util_set_int_elem_from_file (HalDevice *d, const gchar *key,
				 const gchar *directory, const gchar *file,
				 const gchar *linestart, guint elem, guint base, gboolean reuse)
{
	gchar *endptr;
	gboolean res;
	gchar *strvalue;
	int value;

	res = FALSE;

	strvalue = hal_util_grep_string_elem_from_file (directory, file, linestart, elem, reuse);
	if (strvalue == NULL)
		goto out;

	value = strtol (strvalue, &endptr, base);
	if (endptr == strvalue)
		goto out;

	res = hal_device_property_set_int (d, key, value);

out:
	return res;

}

/** Get a value from a formatted text file, test it against a given
 *  value, and set a boolean property on a device object with the
 *  test result.
 *
 *  Example: Given that the file /proc/acpi/battery/BAT0/info contains
 *  the line
 *
 *    "present:                 yes"
 *
 *  then hal_util_set_bool_elem_from_file (d, "battery.baz",
 *  "/proc/acpi/battery/BAT0", "info", "present", 0, "yes") will assign
 *  the boolean TRUE to the property "battery.baz" on d.
 *
 *  If, instead, the line was
 *
 *    "present:                 no"
 *
 *  the value assigned will be FALSE.
 *
 *  @param  d                   Device object
 *  @param  key                 Property name
 *  @param  directory           Directory, e.g. "/proc/acpi/battery/BAT0"
 *  @param  file                File, e.g. "info"
 *  @param  linestart           Start of line, e.g. "design voltage"
 *  @param  elem                Element number after linestart to extract
 *                              excluding whitespace and ':' characters.
 *  @param  expected            Value to test against
 *  @return                     TRUE, if, and only if, the value could be
 *                              extracted and the property was set
 */
gboolean
hal_util_set_bool_elem_from_file (HalDevice *d, const gchar *key,
				  const gchar *directory, const gchar *file,
				  const gchar *linestart, guint elem, const gchar *expected, gboolean reuse)
{
	gchar *line;
	gboolean res;
	gchar **tokens;
	guint i, j;

	res = FALSE;
	tokens = NULL;

	if (((line = hal_util_grep_file (directory, file, linestart, reuse)) == NULL) || (strlen (line) == 0))
		goto out;

	tokens = g_strsplit_set (line, " \t:", 0);

	for (i = 0, j = 0; tokens[i] != NULL; i++) {
		if (strlen (tokens[i]) == 0)
			continue;
		if (j == elem) {
			hal_device_property_set_bool (d, key, strcmp (tokens[i], expected) == 0);
			res = TRUE;
			goto out;
		}
		j++;
	}


out:
	if (tokens != NULL)
		g_strfreev (tokens);

	return res;
}

gchar **
hal_util_dup_strv_from_g_slist (GSList *strlist)
{
	guint j;
	guint len;
	gchar **strv;
	GSList *i;

	len = g_slist_length (strlist);
	strv = g_new (char *, len + 1);

	for (i = strlist, j = 0; i != NULL; i = g_slist_next (i), j++) {
		strv[j] = g_strdup ((const gchar *) i->data);
	}
	strv[j] = NULL;

	return strv;
}

/* -------------------------------------------------------------------------------------------------------------- */

typedef struct {
	HalDevice *d;
	gchar **programs;
	gchar **extra_env;
	guint next_program;

	HalCalloutsDone callback;
	gpointer userdata1;
	gpointer userdata2;

} Callout;

static void callout_do_next (Callout *c);

static void
callout_terminated (HalDevice *d, guint32 exit_type,
                   gint return_code, gchar **error,
                   gpointer data1, gpointer data2)
{
	Callout *c;

	c = (Callout *) data1;
	callout_do_next (c);
}

static void
callout_do_next (Callout *c)
{

	/* Check if we're done */
	if (c->programs[c->next_program] == NULL) {
		HalDevice *d;
		gpointer userdata1;
		gpointer userdata2;
		HalCalloutsDone callback;

		d = c->d;
		userdata1 = c->userdata1;
		userdata2 = c->userdata2;
		callback = c->callback;

		g_strfreev (c->programs);
		g_strfreev (c->extra_env);
		g_free (c);

		callback (d, userdata1, userdata2);

	} else {
    hald_runner_run(c->d, c->programs[c->next_program], c->extra_env,
                    HAL_HELPER_TIMEOUT, callout_terminated,
                    (gpointer)c, NULL);
		c->next_program++;
	}
}

static void
hal_callout_device (HalDevice *d, HalCalloutsDone callback, gpointer userdata1, gpointer userdata2,
		    GSList *programs, gchar **extra_env)
{
	Callout *c;

	c = g_new0 (Callout, 1);
	c->d = d;
	c->callback = callback;
	c->userdata1 = userdata1;
	c->userdata2 = userdata2;
	c->programs = hal_util_dup_strv_from_g_slist (programs);
	c->extra_env = g_strdupv (extra_env);
	c->next_program = 0;

	callout_do_next (c);
}

void
hal_util_callout_device_add (HalDevice *d, HalCalloutsDone callback, gpointer userdata1, gpointer userdata2)
{
	GSList *programs;
	gchar *extra_env[2] = {"HALD_ACTION=add", NULL};

	if ((programs = hal_device_property_get_strlist (d, "info.callouts.add")) == NULL) {
		callback (d, userdata1, userdata2);
		goto out;
	}

	HAL_INFO (("Add callouts for udi=%s", d->udi));

	hal_callout_device (d, callback, userdata1, userdata2, programs, extra_env);
out:
	;
}

void
hal_util_callout_device_remove (HalDevice *d, HalCalloutsDone callback, gpointer userdata1, gpointer userdata2)
{
	GSList *programs;
	gchar *extra_env[2] = {"HALD_ACTION=remove", NULL};

	if ((programs = hal_device_property_get_strlist (d, "info.callouts.remove")) == NULL) {
		callback (d, userdata1, userdata2);
		goto out;
	}

	HAL_INFO (("Remove callouts for udi=%s", d->udi));

	hal_callout_device (d, callback, userdata1, userdata2, programs, extra_env);
out:
	;
}

void
hal_util_callout_device_preprobe (HalDevice *d, HalCalloutsDone callback, gpointer userdata1, gpointer userdata2)
{
	GSList *programs;
	gchar *extra_env[2] = {"HALD_ACTION=preprobe", NULL};

	if ((programs = hal_device_property_get_strlist (d, "info.callouts.preprobe")) == NULL) {
		callback (d, userdata1, userdata2);
		goto out;
	}

	HAL_INFO (("Preprobe callouts for udi=%s", d->udi));

	hal_callout_device (d, callback, userdata1, userdata2, programs, extra_env);
out:
	;
}

gchar *
hal_util_strdup_valid_utf8 (const char *str)
{
	char *endchar;
	char *newstr;
	unsigned int count = 0;

	if (str == NULL)
		return NULL;

	newstr = g_strdup (str);

	while (!g_utf8_validate (newstr, -1, (const char **) &endchar)) {
		*endchar = '?';
		count++;
	}

	if (strlen(newstr) == count)
		return NULL;
	else
		return newstr;
}

void
hal_util_hexdump (const void *mem, unsigned int size)
{
	(void) printf ("Dumping %d=0x%x bytes\n", size, size);
	(void) hexdump_file(mem, size, HDF_DEFAULT, stdout);
}

gboolean
hal_util_is_mounted_by_hald (const char *mount_point)
{
	int i;
	FILE *hal_mtab;
	int hal_mtab_len;
	int num_read;
	char *hal_mtab_buf;
	char **lines;
	gboolean found;

	hal_mtab = NULL;
	hal_mtab_buf = NULL;
	found = FALSE;

	/*HAL_DEBUG (("examining /media/.hal-mtab for %s", mount_point));*/

	hal_mtab = fopen ("/media/.hal-mtab", "r");
	if (hal_mtab == NULL) {
		HAL_ERROR (("Cannot open /media/.hal-mtab"));
		goto out;
	}
	if (fseek (hal_mtab, 0L, SEEK_END) != 0) {
		HAL_ERROR (("Cannot seek to end of /media/.hal-mtab"));
		goto out;
	}
	hal_mtab_len = ftell (hal_mtab);
	if (hal_mtab_len < 0) {
		HAL_ERROR (("Cannot determine size of /media/.hal-mtab"));
		goto out;
	}
	rewind (hal_mtab);

	hal_mtab_buf = g_new0 (char, hal_mtab_len + 1);
	num_read = fread (hal_mtab_buf, 1, hal_mtab_len, hal_mtab);
	if (num_read != hal_mtab_len) {
		HAL_ERROR (("Cannot read from /media/.hal-mtab"));
		goto out;
	}
	fclose (hal_mtab);
	hal_mtab = NULL;

	/*HAL_DEBUG (("hal_mtab = '%s'\n", hal_mtab_buf));*/

	lines = g_strsplit (hal_mtab_buf, "\n", 0);
	g_free (hal_mtab_buf);
	hal_mtab_buf = NULL;

	/* find the entry we're going to unmount */
	for (i = 0; lines[i] != NULL && !found; i++) {
		char **line_elements;

		/*HAL_DEBUG ((" line = '%s'", lines[i]));*/

		if ((lines[i])[0] == '#')
			continue;

		line_elements = g_strsplit (lines[i], "\t", 6);
		if (g_strv_length (line_elements) == 6) {
/*
			HAL_DEBUG (("  devfile     = '%s'", line_elements[0]));
			HAL_DEBUG (("  uid         = '%s'", line_elements[1]));
			HAL_DEBUG (("  session id  = '%s'", line_elements[2]));
			HAL_DEBUG (("  fs          = '%s'", line_elements[3]));
			HAL_DEBUG (("  options     = '%s'", line_elements[4]));
			HAL_DEBUG (("  mount_point = '%s'", line_elements[5]));
			HAL_DEBUG (("  (comparing against '%s')", mount_point));
*/

			if (strcmp (line_elements[5], mount_point) == 0) {
				found = TRUE;
				/*HAL_INFO (("device at '%s' is indeed mounted by HAL's Mount()", mount_point));*/
			}

		}

		g_strfreev (line_elements);
	}

	g_strfreev (lines);

out:
	if (hal_mtab != NULL)
		fclose (hal_mtab);
	if (hal_mtab_buf != NULL)
		g_free (hal_mtab_buf);

	return found;
}

void
hal_util_branch_claim (HalDeviceStore *store, HalDevice *root, dbus_bool_t claimed,
    const char *service, int uid)
{
	GSList *children;
	GSList *i;
	HalDevice *d;

	if (claimed) {
		hal_device_property_set_bool (root, "info.claimed", claimed);
		hal_device_property_set_string (root, "info.claimed.service", service);
		hal_device_property_set_int (root, "info.claimed.uid", uid);
	} else {
		hal_device_property_remove (root, "info.claimed");
		hal_device_property_remove (root, "info.claimed.service");
		hal_device_property_remove (root, "info.claimed.uid");
	}


	children = hal_device_store_match_multiple_key_value_string (store,
	    "info.parent", root->udi);

	for (i = children; i != NULL; i = g_slist_next (i)) {
		d = HAL_DEVICE (i->data);
		hal_util_branch_claim (store, d, claimed, service, uid);
	}

	g_slist_free (children);
}

/** Given an interface name, check if it is valid.
 *  @param  name	A given interface name
 *  @return		TRUE if name is valid, otherwise FALSE
 */
gboolean
is_valid_interface_name(const char *name) {

	const char *end;
	const char *last_dot;

	last_dot = NULL;

	if (strlen(name) == 0)
		return FALSE;

	end = name + strlen(name);

	if (*name == '.')    /* disallow starting with a . */
		return FALSE;
	else if (!VALID_INITIAL_NAME_CHARACTER (*name))
		return FALSE;
	else
		name++;

	while (name != end) {
		if (*name == '.') {
			if ((name + 1) == end)
				return FALSE;
			else if (!VALID_INITIAL_NAME_CHARACTER (*(name + 1)))
				return FALSE;
			last_dot = name;
			name++;    /* we just validated the next char, so skip two */
		} else if (!VALID_NAME_CHARACTER (*name))
			return FALSE;
		name++;
	}
	if (last_dot == NULL)
		return FALSE;

	return TRUE;
}
