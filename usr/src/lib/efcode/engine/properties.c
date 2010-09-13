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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcode/private.h>
#include <fcode/log.h>

void
create_prop(fcode_env_t *env, char *name)
{
	push_a_string(env, name);
	property(env);
}

void
create_int_prop(fcode_env_t *env, char *name, int val)
{
	PUSH(DS, val);
	encode_int(env);
	create_prop(env, name);
}

void
create_string_prop(fcode_env_t *env, char *name, char *val)
{
	push_a_string(env, val);
	encode_string(env);
	create_prop(env, name);
}

static int
addr_cmp(void *a, void *b)
{
	return ((uchar_t *)a == (uchar_t *)b);
}

static void *
add_property_buffer(fcode_env_t *env, int len)
{
	void *data = MALLOC(len+1);
	return (add_resource(&env->propbufs, data, addr_cmp));
}

static void
free_property_buffer(fcode_env_t *env, void *buffer)
{
	free_resource(&env->propbufs, buffer, addr_cmp);
	FREE(buffer);
}

/*
 * Golden Rule:
 * DO NOT cache the value of the head of the property list *before*
 * looking up a property.
 * This routine is also responsible for purging dead properties
 * and that *can* affect the head pointer.
 * you have been warned!
 */
prop_t *
find_property(device_t *d, char *name)
{
	prop_t *p = d->properties, *prev;
	prop_t *found = NULL;

	prev = NULL;
	while (p && !found) {
		if (p->name) {
			if (strcmp(name, p->name) == 0) {
				found = p;
			}
			prev = p;
			p = p->next;
		} else {
			prop_t *dead;

			if (prev)
				prev->next = p->next;
			else {
				/* last prop in chain */
				d->properties = p->next;
			}
			dead = p;
			p = p->next;
			FREE(dead->name);
			FREE(dead->data);
			FREE(dead);
		}
	}
	return (found);
}

static prop_t *
stack_find_property(fcode_env_t *env, device_t *d)
{
	char *propname;

	propname = pop_a_string(env, NULL);
	return (find_property(d, propname));
}

void
property(fcode_env_t *env)
{
	int datalen;
	char *propname, *srcptr;
	prop_t *p;
	device_t *d;

	CHECK_DEPTH(env, 4, "property");
	if (MYSELF) {
		d = MYSELF->device;
	} else {
		d = env->current_device;
		if (!d) {
			void *buffer;

			two_drop(env);
			if ((buffer = pop_a_string(env, NULL)) != NULL)
				free_property_buffer(env, buffer);
			return;
		}
	}
	propname = pop_a_string(env, NULL);
	p = find_property(d, propname);
	if (p == NULL) {
		p = MALLOC(sizeof (prop_t));
		p->next = d->properties;
		d->properties = p;
		p->name = STRDUP(propname);
	} else if (p->data)
		FREE(p->data);	/* release old resources */
	srcptr = pop_a_string(env, &datalen);
	p->data = MALLOC(datalen+1);
	p->size = datalen;
	memcpy(p->data, srcptr, datalen);
	p->data[datalen] = 0;
	if (srcptr)
		free_property_buffer(env, srcptr);
}

prop_t *
lookup_package_property(fcode_env_t *env, char *propname, device_t *d)
{
	prop_t *p;

	p = find_property(d, propname);
	if (p) {
		return (p);
	}
	if (d->vectors.get_package_prop) {
		static prop_t sp;
		fstack_t fail, n;

		/* recreate the FORTH environment for the remote call */
		push_a_string(env, propname);
		REVERT_PHANDLE(env, n, d);
		PUSH(DS, n);
		d->vectors.get_package_prop(env);
		fail = POP(DS);
		if (fail)
			return (NULL);
		sp.size = POP(DS);
		sp.data = (uchar_t *)POP(DS);
		sp.name = propname;
		sp.next = NULL;
		return (&sp);
	}
	return (NULL);
}

void
get_package_property(fcode_env_t *env)
{
	prop_t *p;
	device_t *d;
	char *propname;

	CHECK_DEPTH(env, 3, "get-package-property");
	CONVERT_PHANDLE(env, d, POP(DS));
	propname = pop_a_string(env, NULL);
	p = lookup_package_property(env, propname, d);
	if (p) {
		PUSH(DS, (fstack_t)p->data);
		PUSH(DS, p->size);
		PUSH(DS, FALSE);
	} else
		PUSH(DS, TRUE);
}

void
get_inherited_prop(fcode_env_t *env)
{
	instance_t *ih;
	device_t *dev;
	prop_t *prop;
	char *pname;
	int plen;

	/*
	 * First, we look thru the in-memory device tree for the property.
	 * If we don't find it, we call get_inherited_prop, which "knows" it's
	 * not going to find the property below the attachment point.
	 */

	CHECK_DEPTH(env, 2, "get-inherited-property");
	pname = pop_a_string(env, &plen);
	ih = MYSELF;
	if (ih) {
		for (; ih; ih = ih->parent) {
			dev = ih->device;
			prop = find_property(dev, pname);
			if (prop) {
				PUSH(DS, (fstack_t)prop->data);
				PUSH(DS, (fstack_t)prop->size);
				PUSH(DS, FALSE);
				return;
			}
		}
		if (dev->vectors.get_inherited_prop) {
			push_a_string(env, pname);
			dev->vectors.get_inherited_prop(env);
			return;
		}
	}
	PUSH(DS, TRUE);
}

void
delete_property(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "delete-property");
	if (MYSELF) {
		prop_t *p;

		p = stack_find_property(env, MYSELF->device);
		if (p) {
			/*
			 * write the name as NULL; the space will be free'd
			 * the next time a property lookup passes this node
			 */
			p->name = NULL;
		}
	} else {
		two_drop(env);
	}
}

void
get_my_property(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "get-my-property");
	PUSH(DS, (fstack_t)MYSELF);
	ihandle_to_phandle(env);
	get_package_property(env);
}

void
encode_string(fcode_env_t *env)
{
	char *str;
	char *prop;
	int len;

	CHECK_DEPTH(env, 2, "encode-string");
	str = pop_a_string(env, &len);

	prop = add_property_buffer(env, len);
	memcpy(prop, str, len);
	prop[len] = 0;
	PUSH(DS, (fstack_t)prop);
	PUSH(DS, len + 1);
}

void
encode_int(fcode_env_t *env)
{
	uchar_t *ptr;
	uint32_t p;

	CHECK_DEPTH(env, 1, "encode-int");
	p = POP(DS);
	ptr = add_property_buffer(env, sizeof (uint32_t));

	memcpy(ptr, (char *)&p, sizeof (uint32_t));
	PUSH(DS, (fstack_t)ptr);
	PUSH(DS, sizeof (uint32_t));
}

void
encode_phys(fcode_env_t *env)
{
	uint_t ncells;

	ncells = get_number_of_parent_address_cells(env);
	CHECK_DEPTH(env, ncells, "encode-phys");
	encode_int(env);
	while (--ncells) {
		rot(env);
		encode_int(env);
		encode_plus(env);
	}
}

static fstack_t
get_decoded_int(uchar_t *dp)
{
	uint32_t d;

	memcpy((char *)&d, dp, sizeof (uint32_t));
	return (d);
}

int
get_default_intprop(fcode_env_t *env, char *name, device_t *d, int def)
{
	prop_t *p;

	if (!d)		/* Kludge for testing */
		return (def);
	p = lookup_package_property(env, name, d);
	if (p == NULL)
		return (def);
	return (get_decoded_int(p->data));
}

int
get_num_addr_cells(fcode_env_t *env, device_t *d)
{
	return (get_default_intprop(env, "#address-cells", d, 2));
}

int
get_num_size_cells(fcode_env_t *env, device_t *d)
{
	return (get_default_intprop(env, "#size-cells", d, 1));
}

void
decode_phys(fcode_env_t *env)
{
	char *ptr;
	int len;
	int adr_cells;
	int offset;

	CHECK_DEPTH(env, 2, "decode-phys");
	ptr = pop_a_string(env, &len);

	adr_cells = get_num_addr_cells(env, env->current_device->parent);

	offset = sizeof (uint32_t) * adr_cells;

	PUSH(DS, (fstack_t)(ptr + offset));
	PUSH(DS, len + offset);

	while (adr_cells--) {
		fstack_t d;
		offset -= sizeof (uint32_t);
		d = get_decoded_int((uchar_t *)(ptr + offset));
		PUSH(DS, d);
	}
}

/*
 * 'reg' Fcode 0x116
 */
void
reg_prop(fcode_env_t *env)
{
	fstack_t size;

	CHECK_DEPTH(env, 1, "reg");
	size = POP(DS);
	encode_phys(env);
	PUSH(DS, size);
	encode_int(env);
	encode_plus(env);
	create_prop(env, "reg");
}

void
encode_bytes(fcode_env_t *env)
{
	char *str;
	char *prop;
	int len;

	CHECK_DEPTH(env, 2, "encode-bytes");
	str = pop_a_string(env, &len);
	prop = add_property_buffer(env, len);
	memcpy(prop, str, len);
	prop[len] = 0;
	PUSH(DS, (fstack_t)prop);
	PUSH(DS, len);
}

void
decode_int(fcode_env_t *env)
{
	char *dp;
	fstack_t d;
	int len;

	CHECK_DEPTH(env, 2, "decode-int");
	dp = pop_a_string(env, &len);
	PUSH(DS, (fstack_t)(dp + sizeof (uint32_t)));
	PUSH(DS, len - sizeof (uint32_t));
	d = get_decoded_int((uchar_t *)dp);
	PUSH(DS, d);
}

void
decode_string(fcode_env_t *env)
{
	int plen, len;
	char *dp;

	CHECK_DEPTH(env, 2, "decode-string");
	dp = pop_a_string(env, &plen);
	len = strlen(dp) + 1;
	PUSH(DS, (fstack_t)(dp + len));
	PUSH(DS, plen - len);
	PUSH(DS, (fstack_t)dp);
	PUSH(DS, len - 1);
}

void
encode_plus(fcode_env_t *env)
{
	int len1, len2;
	char *src1, *src2;
	uchar_t *new;

	CHECK_DEPTH(env, 4, "encode+");
	src1 = pop_a_string(env, &len1);
	src2 = pop_a_string(env, &len2);
	new = add_property_buffer(env, len1 + len2);
	if (src2) {
		memcpy(new, src2, len2);
		free_property_buffer(env, src2);
	}
	if (src1) {
		memcpy(new + len2, src1, len1);
		free_property_buffer(env, src1);
	}
	PUSH(DS, (fstack_t)new);
	PUSH(DS, len1 + len2);
}

static void
make_special_property(fcode_env_t *env, char *name)
{
	push_a_string(env, name);
	property(env);
}

void
device_name(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "device-name");
	encode_string(env);
	make_special_property(env, "name");
}

void
model_prop(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "model");
	encode_string(env);
	make_special_property(env, "model");
}

void
device_type(fcode_env_t *env)
{
	CHECK_DEPTH(env, 2, "device-type");
	encode_string(env);
	make_special_property(env, "device_type");
}

/*
 * 'next-property' Fcode implementation.
 */
void
next_property(fcode_env_t *env)
{
	device_t *phandle;
	char *previous;
	prop_t *p;

	CHECK_DEPTH(env, 3, "next-property");
	phandle = (device_t *)POP(DS);
	previous = pop_a_string(env, NULL);
	p = phandle->properties;
	if (previous == NULL)
		p = phandle->properties;
	else if (p = find_property(phandle, previous))
		p = p->next;

	for (; p != NULL && p->name == NULL; p = p->next)
		;

	if (p)
		push_a_string(env, p->name);
	else
		push_a_string(env, "");
	PUSH(DS, TRUE);
}

void
get_property(fcode_env_t *env)
{
	if (MYSELF)
		get_my_property(env);
	else if (env->current_device) {
		fstack_t d;

		REVERT_PHANDLE(env, d, env->current_device);
		PUSH(DS, d);
		get_package_property(env);
	} else {
		two_drop(env);
		log_message(MSG_WARN, "No device context\n");
	}
}

#ifdef DEBUG

static void
print_indented(char *name)
{
	log_message(MSG_INFO, "%-28s", name);
}

static void
print_string(fcode_env_t *env, uchar_t *data, int len)
{
	while (len > 0) {
		int nlen = (strlen((char *)data)+1);
		log_message(MSG_INFO, "%s\n", data);
		len -= nlen;
		data += nlen;
		if (len > 0)
			print_indented("");
	}
}

static void
print_ints(uchar_t *data, int len, int crlf)
{
	uint32_t d;

	while (len--) {
		d = get_decoded_int(data);
		log_message(MSG_INFO, "%8.8lx ", d);
		data += sizeof (uint32_t);
	}
	if (crlf)
		log_message(MSG_INFO, "\n");
}

static void
print_integer(fcode_env_t *env, uchar_t *data, int len)
{
	print_ints(data, len/sizeof (uint32_t), 1);
}

static void
print_bytes(fcode_env_t *env, uchar_t *data, int len)
{
	while (len--) {
		log_message(MSG_INFO, "%2.2x ", *data++);
	}
	log_message(MSG_INFO, "\n");
}

static void
print_bytes_indented(fcode_env_t *env, uchar_t *data, int len)
{
	int nbytes;

	for (; ; ) {
		nbytes = min(len, 16);
		print_bytes(env, data, nbytes);
		len -= nbytes;
		data += nbytes;
		if (len == 0)
			break;
		print_indented("");
	}
}

static void
print_reg(fcode_env_t *env, uchar_t *data, int len)
{
	int pcells, nlen;

	if (env->current_device != NULL &&
	    env->current_device->parent != NULL) {
		pcells = get_num_size_cells(env, env->current_device->parent);
		pcells +=  get_num_addr_cells(env, env->current_device->parent);
		nlen = pcells*sizeof (uint32_t);
		while (len > 0) {
			print_ints(data, pcells, 1);
			len -= nlen;
			data += nlen;
			if (len > 0)
				print_indented("");
		}
	} else
		print_bytes_indented(env, data, len);
}

static void
print_imap(fcode_env_t *env, uchar_t *dp, int len)
{
	int n, icells;

	if (env->current_device == NULL) {
		print_bytes_indented(env, dp, len);
		return;
	}
	n = get_num_addr_cells(env, env->current_device);

	while (len) {
		int offset;
		fstack_t data;
		device_t *node;

		offset = 0;
		data = get_decoded_int(dp+((n+1)*sizeof (uint32_t)));
		CONVERT_PHANDLE(env, node, data);
		offset += (n+2)*sizeof (uint32_t);
		print_ints(dp, (n+2), 0);
		icells = get_default_intprop(env, "#interrupt-cells", node, 1);
		print_ints(dp+offset, icells, 1);
		offset += icells*sizeof (uint32_t);
		dp += offset;
		len -= offset;
		if (len)
			print_indented("");
	}
}

static void
print_ranges(fcode_env_t *env, uchar_t *data, int len)
{
	int pcells, nlen;

	if (env->current_device != NULL &&
	    env->current_device->parent != NULL) {
		pcells = get_num_addr_cells(env, env->current_device);
		pcells += get_num_addr_cells(env, env->current_device->parent);
		pcells += get_num_size_cells(env, env->current_device);
		nlen = pcells*sizeof (uint32_t);
		while (len > 0) {
			print_ints(data, pcells, 1);
			len -= nlen;
			data += nlen;
			if (len > 0)
				print_indented("");
		}
	} else
		print_bytes_indented(env, data, len);
}

typedef struct MAGIC_PROP {
	char *name;
	void (*fn)(fcode_env_t *env, uchar_t *data, int len);
} magic_prop_t;

static magic_prop_t magic_props[] = {
	{ "name",		print_string },
	{ "device_type",	print_string },
	{ "model",		print_string },
	{ "reg",		print_reg },
	{ "assigned-addresses",	print_reg },
	{ "interrupt-map",	print_imap },
	{ "#interrupt-cells",	print_integer },
	{ "interrupt-map-mask",	print_integer },
	{ "#size-cells",	print_integer },
	{ "#address-cells",	print_integer },
	{ "ranges",		print_ranges },
	{ "device-id",		print_integer },
	{ "vendor-id",		print_integer },
	{ "class-code",		print_integer },
	{ "compatible",		print_string },
	{ "version",		print_string },
	{ "manufacturer",	print_string },
	{ NULL, NULL }
};

static void
print_content(fcode_env_t *env, char *prop, uchar_t *data, int len)
{
	magic_prop_t *p;

	for (p = magic_props; p->name; p++)
		if (strcmp(prop, p->name) == 0) {
			(*p->fn)(env, data, len);
			return;
		}
	print_bytes_indented(env, data, len);
}

void
print_property(fcode_env_t *env, prop_t *p, char *prepend)
{
	char buf[40];
	char *name = (p->name ? p->name : "<noname>");

	if (prepend) {
		sprintf(buf, "%s %s", prepend, name);
		name = buf;
	}
	print_indented(name);
	if (p->name)
		print_content(env, p->name, p->data, p->size);
	else
		print_bytes_indented(env, p->data, p->size);
}

void
dot_properties(fcode_env_t *env)
{
	prop_t *p;
	instance_t *omyself;

	omyself = MYSELF;
	MYSELF = NULL;

	if (env->current_device) {
		for (p = env->current_device->properties; p; p = p->next)
			print_property(env, p, NULL);
	} else {
		log_message(MSG_INFO, "No device context\n");
	}
	MYSELF = omyself;
}

#endif

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

	P1275(0x110, 0,		"property",		property);
	P1275(0x111, 0,		"encode-int",		encode_int);
	P1275(0x112, 0,		"encode+",		encode_plus);
	P1275(0x113, 0,		"encode-phys",		encode_phys);
	P1275(0x114, 0,		"encode-string",	encode_string);
	P1275(0x115, 0,		"encode-bytes",		encode_bytes);
	P1275(0x116, 0,		"reg",			reg_prop);
	FCODE(0x117, 0,		"intr",			fc_obsolete);
	FCODE(0x118, 0,		"driver",		fc_historical);
	P1275(0x119, 0,		"model",		model_prop);
	P1275(0x11a, 0,		"device-type",		device_type);

	P1275(0x128, 0,		"decode-phys",		decode_phys);

	P1275(0x201, 0,		"device-name",		device_name);

	P1275(0x21a, 0,		"get-my-property",	get_my_property);
	P1275(0x21b, 0,		"decode-int",		decode_int);
	P1275(0x21c, 0,		"decode-string",	decode_string);
	P1275(0x21d, 0,		"get-inherited-property", get_inherited_prop);
	P1275(0x21e, 0,		"delete-property",	delete_property);
	P1275(0x21f, 0,		"get-package-property",	get_package_property);

	P1275(0x23d, 0,		"next-property",	next_property);

	FORTH(0,		"get-property",		get_property);
	FORTH(0,		".properties",		dot_properties);
}
