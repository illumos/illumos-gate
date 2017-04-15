/***************************************************************************
 * CVSID: $Id$
 *
 * hal-device.c : add devices HAL
 *
 * Copyright (C) 2005 SuSE Linux Gmbh
 *
 * Authors:
 *	Steffen Winterfeldt <snwint@suse.de>
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
 */

#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>
#include <getopt.h>

#ifndef DBUS_API_SUBJECT_TO_CHANGE
#define DBUS_API_SUBJECT_TO_CHANGE 1
#endif

#include <dbus/dbus.h>
#include <libhal.h>

typedef struct {
	char *udi;
	char *real_udi;
} new_dev_t;

typedef struct lh_prop_s {
	struct lh_prop_s *next;
	LibHalPropertyType type;
	char *key;
	union {
		char *str_value;
		dbus_int32_t int_value;
		dbus_uint64_t uint64_value;
		double double_value;
		dbus_bool_t bool_value;
		char **strlist_value;
	} v;
} lh_prop_t;


void help(void);
int dump_devices(LibHalContext *hal_ctx, char *arg);
int remove_udi(LibHalContext *hal_ctx, char *arg);
int add_udi(LibHalContext *hal_ctx, char *arg);
void process_property(LibHalContext *hal_ctx, char *buf, lh_prop_t **prop);
int add_properties(LibHalContext *hal_ctx, new_dev_t *nd, lh_prop_t *prop);
lh_prop_t *free_properties(lh_prop_t *prop);
static char *skip_space(char *s);
static char *skip_non_eq_or_space(char *s);
static char *skip_number(char *s);
static char *skip_nonquote(char *s);


new_dev_t new_dev;

struct {
	unsigned remove:1;
	unsigned add:1;
	unsigned list:1;
	char *udi;
} opt;

struct option options[] = {
	{ "remove", 1, NULL, 'r' },
	{ "add", 1, NULL, 'a' },
	{ "help", 0, NULL, 'h' },
	{ 0, 0, 0, 0 }
};


int main(int argc, char **argv)
{
	DBusError error;
	DBusConnection *conn;
	LibHalContext *hal_ctx;
	int i, err;

	opterr = 0;
	opt.list = 1;

	while ((i = getopt_long(argc, argv, "a:hr:", options, NULL)) != -1) {
		switch (i) {
		case 'a':
			opt.add = 1;
			opt.list = 0;
			opt.udi = optarg;
			break;
		case 'r':
			opt.remove = 1;
			opt.list = 0;
			opt.udi = optarg;
			break;
		case 'h':
			help();
			return 0;
		default:
			help();
			return 1;
		}
	}

	dbus_error_init(&error);

	if (!(conn = dbus_bus_get(DBUS_BUS_SYSTEM, &error))) {
		fprintf(stderr, "error: dbus_bus_get: %s: %s\n", error.name, error.message);
		LIBHAL_FREE_DBUS_ERROR (&error);
		return 2;
	}

	/* fprintf(stderr, "connected to: %s\n", dbus_bus_get_unique_name(conn)); */
	if (!(hal_ctx = libhal_ctx_new())) return 3;
	if (!libhal_ctx_set_dbus_connection(hal_ctx, conn)) return 4;
	if (!libhal_ctx_init(hal_ctx, &error)) {
		if (dbus_error_is_set(&error)) {
			fprintf (stderr, "error: libhal_ctx_init: %s: %s\n", error.name, error.message);
			LIBHAL_FREE_DBUS_ERROR (&error);
		}
		fprintf (stderr, "Could not initialise connection to hald.\n"
				 "Normally this means the HAL daemon (hald) is not running or not ready.\n");
		return 5;
	}

	err = 0;
	if (opt.list)
		err = dump_devices(hal_ctx, argv[optind]);
	else if (opt.remove)
		err = remove_udi(hal_ctx, opt.udi);
	else if (opt.add)
		err = add_udi(hal_ctx, opt.udi);
	else
		err = 6;

	libhal_ctx_shutdown(hal_ctx, &error);
	libhal_ctx_free(hal_ctx);
	dbus_connection_unref(conn);
	dbus_error_free(&error);

	return err;
}


void help()
{
	fprintf(stderr,
		"usage: hal-device [--help] [--add udi] [--remove udi] [udi]\n"
		"Create, remove, or show HAL device. If no udi is given, shows all devices.\n"
		"If udi doesn't start with a '/', '/org/freedesktop/Hal/devices/' is prepended.\n"
		"  -a, --add udi\t\tAdd new device.\n"
		"  \t\t\tReads property list in 'lshal' syntax from stdin.\n"
		"  -r, --remove udi\tRemove device.\n"
		"  -h, --help\t\tShow this text.\n"
	);
}


/*
 * Dump all devices.
 */
int dump_devices(LibHalContext *hal_ctx, char *arg)
{
	int i;
	int num_devices;
	char **device_names;
	DBusError error;
	char *udi = NULL;

	if (arg) {
		if (*arg == '/') {
			udi = arg;
		} else {
#ifdef HAVE_ASPRINTF
			asprintf(&udi, "/org/freedesktop/Hal/devices/%s", arg);
#else
			udi = calloc(1, sizeof ("/org/freedesktop/Hal/devices/%s") + strlen(arg));
			sprintf(udi, "/org/freedesktop/Hal/devices/%s", arg);

#endif
		}
	}

	dbus_error_init(&error);

	if (!udi) {
		if (!(device_names = libhal_get_all_devices(hal_ctx, &num_devices, &error))) {
			fprintf(stderr, "Empty HAL device list.\n");
			LIBHAL_FREE_DBUS_ERROR (&error);
			return 31;
		}
	} else {
		device_names = calloc(2, sizeof *device_names);
		device_names[0] = strdup(udi);
		num_devices = 1;
	}

	for(i = 0; i < num_devices; i++) {
		LibHalPropertySet *props;
		LibHalPropertySetIterator it;
		int type;

		if (!(props = libhal_device_get_all_properties(hal_ctx, device_names[i], &error))) {
			fprintf(stderr, "%s: %s\n", error.name, error.message);
			dbus_error_init(&error);
			continue;
		}

		if (!udi)
			printf("%d: ", i);
		printf("udi = '%s'\n", device_names[i]);

		for(libhal_psi_init(&it, props); libhal_psi_has_more(&it); libhal_psi_next(&it)) {
			type = libhal_psi_get_type(&it);
			switch (type) {
			case LIBHAL_PROPERTY_TYPE_STRING:
				printf("  %s = '%s'  (string)\n",
					libhal_psi_get_key(&it),
					libhal_psi_get_string(&it)
				);
				break;
			case LIBHAL_PROPERTY_TYPE_INT32:
				printf("  %s = %d  (0x%x)  (int)\n",
					libhal_psi_get_key(&it),
					libhal_psi_get_int(&it),
					libhal_psi_get_int(&it)
				);
				break;
			case LIBHAL_PROPERTY_TYPE_UINT64:
				printf("  %s = %lld  (0x%llx)  (uint64)\n",
					libhal_psi_get_key(&it),
					(long long) libhal_psi_get_uint64(&it),
					(long long) libhal_psi_get_uint64(&it)
				);
				break;
			case LIBHAL_PROPERTY_TYPE_DOUBLE:
				printf("  %s = %g  (double)\n",
					libhal_psi_get_key(&it),
					libhal_psi_get_double(&it)
				);
				break;
			case LIBHAL_PROPERTY_TYPE_BOOLEAN:
				printf("  %s = %s  (bool)\n",
					libhal_psi_get_key(&it),
					libhal_psi_get_bool(&it) ? "true" : "false"
				);
				break;
			case LIBHAL_PROPERTY_TYPE_STRLIST:
				{
					char **strlist;

					printf ("  %s = { ", libhal_psi_get_key(&it));
					strlist = libhal_psi_get_strlist(&it);
					while (*strlist) {
						printf("'%s'%s", *strlist, strlist[1] ? ", " : "");
						strlist++;
					}
					printf(" } (string list)\n");
				}
				break;
			default:
				printf("Unknown type %d = 0x%02x\n", type, type);
				break;
			}
		}

		libhal_free_property_set(props);
		printf("\n");
	}

	libhal_free_string_array(device_names);
	dbus_error_free(&error);

	return 0;
}


int remove_udi(LibHalContext *hal_ctx, char *arg)
{
	DBusError error;
	char *udi;

	if (!arg) return 11;

	if (*arg == '/') {
		udi = arg;
	} else {
#ifdef HAVE_ASPRINTF
		asprintf(&udi, "/org/freedesktop/Hal/devices/%s", arg);
#else
		udi = calloc(1, sizeof ("/org/freedesktop/Hal/devices/%s") + strlen(arg));
		sprintf(udi, "/org/freedesktop/Hal/devices/%s", arg);
#endif

	}

	dbus_error_init(&error);

	if (opt.remove) {
		if (!libhal_remove_device(hal_ctx, udi, &error)) {
			fprintf(stderr, "%s: %s\n", error.name, error.message);
			LIBHAL_FREE_DBUS_ERROR (&error);
			return 12;
		}

		fprintf(stderr, "removed: %s\n", udi);
		return 13;
	}

	return 0;
}


int add_udi(LibHalContext *hal_ctx, char *arg)
{
	DBusError error;
	dbus_bool_t dev_exists = FALSE;
	char *udi = NULL, buf[1024];
	lh_prop_t *prop;
	int err;

	if (!arg)
		return 21;

	if (*arg == '/') {
		udi = arg;
	} else {
#ifdef HAVE_ASPRINTF
		asprintf(&udi, "/org/freedesktop/Hal/devices/%s", arg);
#else
		udi = calloc(1, sizeof ("/org/freedesktop/Hal/devices/%s") + strlen(arg));
		sprintf(udi, "/org/freedesktop/Hal/devices/%s", arg);
#endif
	}

	if (udi)
		new_dev.udi = strdup(udi);

	dbus_error_init(&error);

	if (udi)
		dev_exists = libhal_device_exists(hal_ctx, udi, &error);

	if (dev_exists) {
		new_dev.real_udi = strdup(new_dev.udi);
	} else {
		new_dev.real_udi = libhal_new_device(hal_ctx, &error);

		if (!new_dev.real_udi) {
			fprintf(stderr, "%s: %s\n", error.name, error.message);
			LIBHAL_FREE_DBUS_ERROR (&error);
			free(new_dev.real_udi);

			return 22;
		}

		printf("tmp udi: %s\n", new_dev.real_udi);
	}

	prop = NULL;

	while (fgets(buf, sizeof buf, stdin)) {
		process_property(hal_ctx, buf, &prop);
	}

	err = add_properties(hal_ctx, &new_dev, prop);

	prop = free_properties(prop);

	if (!dev_exists) {
		if (!libhal_device_commit_to_gdl(hal_ctx, new_dev.real_udi, new_dev.udi, &error)) {
			fprintf(stderr, "%s: %s\n", error.name, error.message);
			LIBHAL_FREE_DBUS_ERROR (&error);
			free(new_dev.real_udi);

			err = err ? err : 23;
		}
	}

	printf("%s: %s\n", dev_exists ? "merged": "created", new_dev.udi);

	return err;
}


char *skip_space(char *s)
{
	while (isspace(*s)) s++;

	return s;
}


char *skip_non_eq_or_space(char *s)
{
	while (*s && *s != '=' && !isspace(*s))
		s++;

	return s;
}


char *skip_number(char *s)
{
	while (*s == '-' || *s == '+' || *s == '.' || isdigit(*s))
		s++;

	return s;
}


char *skip_nonquote(char *s)
{
	while (*s && *s != '\'')
		s++;

	return s;
}


void process_property(LibHalContext *hal_ctx, char *buf, lh_prop_t **prop)
{
	char *s, *s1;
	char *key, *s_val = NULL;
	lh_prop_t *p;
	unsigned len;
	int remove = 0;

	s = skip_space(buf);

	if (*s == '-') {
		remove = 1;
		s = skip_space(s + 1);
	}

	if ((s1 = skip_number(s), s1 != s) && *s1 == ':') s = skip_space(s1 + 1);

	s = skip_non_eq_or_space(key = s);
	*s++ = 0;
	if (!*key)
		return;

	if (*key == '#')
		return;

	if (*s == '=')
		s++;
	s = skip_space(s);

	if (!*s)
		remove = 1;

	p = calloc(1, sizeof *p);
	p->type = LIBHAL_PROPERTY_TYPE_INVALID;
	p->key = strdup(key);

	if (remove) {
		p->next = *prop;
		*prop = p;
		return;
	}

	if (*s == '\'') {
		s_val = s + 1;
		s = strrchr(s_val, '\'');
		*(s ? s : s_val) = 0;
		p->type = LIBHAL_PROPERTY_TYPE_STRING;
		p->v.str_value = strdup(s_val);
	} else if (*s == '{') {
		s_val = s + 1;
		s1 = strrchr(s_val, '}');
		if (s1) *s1 = 0;
		p->type = LIBHAL_PROPERTY_TYPE_STRLIST;
		len = 0;
		p->v.strlist_value = calloc(1, sizeof *p->v.strlist_value);
		while (*s_val++ == '\'') {
			s = skip_nonquote(s_val);
			if (*s) *s++ = 0;
			p->v.strlist_value = realloc(p->v.strlist_value, (len + 2) * sizeof *p->v.strlist_value);
			p->v.strlist_value[len] = strdup(s_val);
			p->v.strlist_value[++len] = NULL;
			s_val = skip_nonquote(s);
		}
	} else if (!strncmp(s, "true", 4)) {
		s += 4;
		p->type = LIBHAL_PROPERTY_TYPE_BOOLEAN;
		p->v.bool_value = TRUE;
	} else if (!strncmp(s, "false", 5)) {
		s += 5;
		p->type = LIBHAL_PROPERTY_TYPE_BOOLEAN;
		p->v.bool_value = FALSE;
	} else if ((s1 = skip_number(s)) != s) {
		if (strstr(s1, "(int)")) {
			*s1++ = 0;
			p->type = LIBHAL_PROPERTY_TYPE_INT32;
			p->v.int_value = strtol(s, NULL, 10);
		} else if (strstr(s1, "(uint64)")) {
			*s1++ = 0;
			p->type = LIBHAL_PROPERTY_TYPE_UINT64;
			p->v.uint64_value = strtoull(s, NULL, 10);
		} else if (strstr(s1, "(double)")) {
			p->type = LIBHAL_PROPERTY_TYPE_DOUBLE;
			p->v.double_value = strtod(s, NULL);
		}

		s = s1;
	}

	if (p->type == LIBHAL_PROPERTY_TYPE_INVALID) {
		free(p->key);
		free(p);
	} else {
		p->next = *prop;
		*prop = p;
	}
}


int add_properties(LibHalContext *hal_ctx, new_dev_t *nd, lh_prop_t *prop)
{
	DBusError error;
	lh_prop_t *p;
	char *udi2 = NULL, *udi3 = NULL, **s;
	LibHalPropertyType old_type;

	dbus_error_init(&error);

	for(p = prop; p; p = p->next) {
		if (!strcmp(p->key, "udi") && p->type == LIBHAL_PROPERTY_TYPE_STRING) {
			udi2 = p->v.str_value;
			continue;
		}

		old_type = libhal_device_get_property_type(hal_ctx, nd->real_udi, p->key, &error);
		dbus_error_init(&error);

		if (old_type != LIBHAL_PROPERTY_TYPE_INVALID &&
		    ( p->type != old_type || p->type == LIBHAL_PROPERTY_TYPE_STRLIST)) {
			if (!libhal_device_remove_property(hal_ctx, nd->real_udi, p->key, &error)) {
				fprintf(stderr, "%s: %s\n", error.name, error.message);
				LIBHAL_FREE_DBUS_ERROR (&error);
				return 41;
			}
		}

		switch (p->type) {
			case LIBHAL_PROPERTY_TYPE_BOOLEAN:
				if (!libhal_device_set_property_bool(hal_ctx, nd->real_udi, p->key, p->v.bool_value, &error)) {
					fprintf(stderr, "%s: %s\n", error.name, error.message);
					LIBHAL_FREE_DBUS_ERROR (&error);
					return 42;
				}
				break;
			case LIBHAL_PROPERTY_TYPE_INT32:
				if (!libhal_device_set_property_int(hal_ctx, nd->real_udi, p->key, p->v.int_value, &error)) {
					fprintf(stderr, "%s: %s\n", error.name, error.message);
					LIBHAL_FREE_DBUS_ERROR (&error);
					return 42;
				}
				break;
			case LIBHAL_PROPERTY_TYPE_UINT64:
				if (!libhal_device_set_property_uint64(hal_ctx, nd->real_udi, p->key, p->v.uint64_value, &error)) {
					fprintf(stderr, "%s: %s\n", error.name, error.message);
					LIBHAL_FREE_DBUS_ERROR (&error);
					return 42;
				}
				break;
			case LIBHAL_PROPERTY_TYPE_DOUBLE:
				if (!libhal_device_set_property_double(hal_ctx, nd->real_udi, p->key, p->v.double_value, &error)) {
					fprintf(stderr, "%s: %s\n", error.name, error.message);
					LIBHAL_FREE_DBUS_ERROR (&error);
					return 42;
				}
				break;
			case LIBHAL_PROPERTY_TYPE_STRING:
				if (!strcmp(p->key, "info.udi")) udi3 = p->v.str_value;
				if (!libhal_device_set_property_string(hal_ctx, nd->real_udi, p->key, p->v.str_value, &error)) {
					fprintf(stderr, "%s: %s\n", error.name, error.message);
					LIBHAL_FREE_DBUS_ERROR (&error);
					return 42;
				}
				break;
			case LIBHAL_PROPERTY_TYPE_STRLIST:
				for(s = p->v.strlist_value; *s; s++) {
					if (!libhal_device_property_strlist_append(hal_ctx, nd->real_udi, p->key, *s, &error)) {
						fprintf(stderr, "%s: %s\n", error.name, error.message);
						LIBHAL_FREE_DBUS_ERROR (&error);
						return 42;
					}
				}
				break;
			default:
				break;
		}
	}

	if (udi2) udi3 = NULL;
	if (udi3) udi2 = udi3;

	if (udi2 && !nd->udi)
		nd->udi = strdup(udi2);

	return 0;
}


lh_prop_t *free_properties(lh_prop_t *prop)
{
	lh_prop_t *next;
	char **s;

	for(; prop; prop = next) {
		next = prop->next;

		free(prop->key);
		if (prop->type == LIBHAL_PROPERTY_TYPE_STRING) free(prop->v.str_value);
		if (prop->type == LIBHAL_PROPERTY_TYPE_STRLIST && prop->v.strlist_value) {
			for(s = prop->v.strlist_value; *s; ) free(*s++);
			free(prop->v.strlist_value);
		}
		free(prop);
	}

	return NULL;
}
