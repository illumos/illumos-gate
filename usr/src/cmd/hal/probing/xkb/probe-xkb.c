/***************************************************************************
 *
 * probe-xkb.c : Probe for keyboard device information
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stropts.h>
#include <fcntl.h>
#include <unistd.h>
#include <priv.h>

#include <sys/kbd.h>
#include <sys/kbio.h>

#include <libhal.h>
#include <logger.h>

#define	MAXLINELEN		256
#define	COMMENTCHAR		'#'
#define	KBD_DEFAULT_DEVICE	"/dev/kbd"
#define	XKBTABLE_PATH		"/usr/X11/lib/X11/xkb/xkbtable.map"

static int		global_linenumber = 0;
static char		line[MAXLINELEN + 1];

static void
drop_privileges()
{
	priv_set_t *pPrivSet = NULL;
	priv_set_t *lPrivSet = NULL;

	/*
	 * Start with the 'basic' privilege set and then remove any
	 * of the 'basic' privileges that will not be needed.
	 */
	if ((pPrivSet = priv_str_to_set("basic", ",", NULL)) == NULL) {
		HAL_INFO(("Error in setting the priv"));
		return;
	}

	/* Clear privileges we will not need from the 'basic' set */
	(void) priv_delset(pPrivSet, PRIV_FILE_LINK_ANY);
	(void) priv_delset(pPrivSet, PRIV_PROC_INFO);
	(void) priv_delset(pPrivSet, PRIV_PROC_SESSION);
	(void) priv_delset(pPrivSet, PRIV_PROC_EXEC);
	(void) priv_delset(pPrivSet, PRIV_PROC_FORK);

	(void) priv_addset(pPrivSet, PRIV_SYS_DEVICES);
	(void) priv_addset(pPrivSet, PRIV_FILE_DAC_READ);

	/* Set the permitted privilege set. */
	if (setppriv(PRIV_SET, PRIV_PERMITTED, pPrivSet) != 0) {
		return;
	}

	/* Clear the limit set. */
	if ((lPrivSet = priv_allocset()) == NULL) {
		return;
	}

	priv_emptyset(lPrivSet);

	if (setppriv(PRIV_SET, PRIV_LIMIT, lPrivSet) != 0) {
		return;
	}

	priv_freeset(lPrivSet);
	priv_freeset(pPrivSet);
}

static int
get_kbd_layout_type(char *device_file, int *kbd_type, int *kbd_layout)
{
	int ret = 1;
	int fd = -1;

	if ((fd = open(device_file, O_RDONLY | O_NONBLOCK)) < 0) {
		HAL_DEBUG(("Cannot open %s: %s", device_file, strerror(errno)));
		goto out;
	}

	/*
	 * For usb keyboard devices, we need to first push "usbkbm" module upon
	 * the stream.
	 */
	if (strstr(device_file, "hid") != NULL) {
		if (ioctl(fd, I_FIND, "usbkbm") == 0) {
			(void) ioctl(fd, I_PUSH, "usbkbm");
			HAL_DEBUG(("usbkbm module has been pushed %s", strerror(errno)));
		}
	}

	if (ioctl(fd, KIOCTYPE, kbd_type) < 0) {
		HAL_DEBUG(("get keyboard type failed %s: %s",
		    device_file, strerror(errno)));
		goto out;
	}
	if (ioctl(fd, KIOCLAYOUT, kbd_layout) < 0) {
		HAL_DEBUG(("get keyboard layout failed %s: %s",
		    device_file, strerror(errno)));
		goto out;
	}

	ret = 0;

out:	if (fd >= 0) {
		close(fd);
	}

	return (ret);
}

/* Skips over the white space character in the string. */
static char *
skipwhite(char *ptr)
{
	while ((*ptr == ' ') || (*ptr == '\t')) {
		ptr++;
	}

	/* This should not occur. but .. */
	if (*ptr == '\n') {
		ptr = '\0';
	}

	return (ptr);
}

static char *
getaline(FILE *fp)
{
	char    *ptr;
	char    *tmp;
	int	index;
	int	c;

	while (1) {
		ptr = fgets(line, MAXLINELEN, fp);
		if (!ptr) {
			(void) fclose(fp);
			return (NULL);
		}

		global_linenumber++;

		/* Comment line */
		if (ptr[0] == COMMENTCHAR) {
			continue;
		}

		/* Blank line */
		if (ptr[0] == '\n') {
			continue;
		}

		if ((tmp = strchr(ptr, '#')) != NULL) {
			*tmp = '\0';
		}

		if (ptr[strlen(ptr) - 1] == '\n') {
			/* get rid of '\n' */
			ptr[strlen(ptr) - 1] = '\0';
		}

		ptr = skipwhite(ptr);
		if (*ptr) {
			break;
		}
	}
	return (ptr);
}

static int
sun_find_xkbnames(int kb_type, int kb_layout, char **xkb_keymap,
    char **xkb_model, char **xkb_layout)
{
	const char  *type, *layout;
	char	*keymap, *defkeymap = NULL;
	char	*model, *defmodel = NULL;
	char	*xkblay, *defxkblay = NULL;
	FILE	*fp;
	int	found_error = 0, found_keytable = 0;
	int	ret = 1;

	if ((fp = fopen(XKBTABLE_PATH, "r")) == NULL) {
		return (ret);
	}

	global_linenumber = 0;
	while (getaline(fp)) {
		if ((type = strtok(line, " \t\n")) == NULL) {
			found_error = 1;
		}

		if ((layout = strtok(NULL, " \t\n")) == NULL) {
			found_error = 1;
		}

		if ((keymap = strtok(NULL, " \t\n")) == NULL) {
			found_error = 1;
		}

		/* These two are optional entries */
		model = strtok(NULL, " \t\n");
		if ((model == NULL) || (*model == COMMENTCHAR)) {
			model = xkblay = NULL;
		} else {
			xkblay = strtok(NULL, " \t\n");
			if ((xkblay != NULL) && (*xkblay == COMMENTCHAR)) {
			xkblay = NULL;
			}
		}

		if (found_error) {
			found_error = 0;
			continue;
		}

		/* record default entry if/when found */
		if (*type == '*') {
			if (defkeymap == NULL) {
				defkeymap = strdup(keymap);
				defmodel = strdup(model);
				defxkblay = strdup(xkblay);
			}
		} else if (atoi(type) == kb_type) {
			if (*layout == '*') {
				defkeymap = strdup(keymap);
				defmodel = strdup(model);
				defxkblay = strdup(xkblay);
			} else if (atoi(layout) == kb_layout) {
				found_keytable = 1;
				break;
			}
		}
	}

	(void) fclose(fp);

	if (!found_keytable) {
		keymap = defkeymap;
		model = defmodel;
		xkblay = defxkblay;
	}

	if ((keymap != NULL) && (strcmp(keymap, "-") != 0)) {
		*xkb_keymap = keymap;
	}
	if ((model != NULL) && (strcmp(model, "-") != 0)) {
		*xkb_model = model;
	}
	if ((xkblay != NULL) && (strcmp(xkblay, "-") != 0)) {
		*xkb_layout = xkblay;
	}

	return (0);
}

int
main(int argc, char *argv[])
{
	int ret = 1;
	char *udi;
	char *device_file;
	LibHalContext *ctx = NULL;
	LibHalChangeSet *cs = NULL;
	DBusError error;
	int kbd_type, kbd_layout;
	char *xkbkeymap = NULL, *xkbmodel = NULL, *xkblayout = NULL;

	if ((udi = getenv("UDI")) == NULL) {
		goto out;
	}

	if ((device_file = getenv("HAL_PROP_INPUT_DEVICE")) == NULL) {
		goto out;
	}

	drop_privileges();
	setup_logger();

	dbus_error_init(&error);
	if ((ctx = libhal_ctx_init_direct(&error)) == NULL) {
		goto out;
	}

	if ((cs = libhal_device_new_changeset(udi)) == NULL) {
		HAL_DEBUG(("Cannot allocate changeset"));
		goto out;
	}

	HAL_DEBUG(("Doing probe-xkb for %s (udi=%s)", device_file, udi));

	if (get_kbd_layout_type(device_file, &kbd_type, &kbd_layout)) {
		goto out;
	}

	/*
	 * For some usb keyboard that is not self-identifying, get keyboard's
	 * layout and type from system default keyboard device--/dev/kbd.
	 */
	if ((kbd_layout == 0) && (strstr(device_file, "hid") != NULL)) {
		if (get_kbd_layout_type(KBD_DEFAULT_DEVICE,
		    &kbd_type, &kbd_layout)) {
			goto out;
		}
	}

	if (sun_find_xkbnames(kbd_type, kbd_layout,
	    &xkbkeymap, &xkbmodel, &xkblayout)) {
		goto out;
	}

	/*
	 * If doesn't find matching entry in xkbtable.map, using default
	 * values setting in 10-x11-input.fdi
	 */
	if ((xkbmodel != NULL) && (xkblayout != NULL)) {
		libhal_changeset_set_property_string(cs,
		    "input.x11_options.XkbModel", xkbmodel);
		libhal_changeset_set_property_string(cs,
		    "input.x11_options.XkbLayout", xkblayout);

		libhal_device_commit_changeset(ctx, cs, &error);
	}

	ret = 0;

out:
	if (cs != NULL) {
		libhal_device_free_changeset(cs);
	}

	if (ctx != NULL) {
		libhal_ctx_shutdown(ctx, &error);
		libhal_ctx_free(ctx);
		if (dbus_error_is_set(&error)) {
			dbus_error_free(&error);
		}
	}
	return (ret);
}
