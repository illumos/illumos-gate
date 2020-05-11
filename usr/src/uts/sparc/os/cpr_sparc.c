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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * cpr functions for supported sparc platforms
 */
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cpr.h>
#include <sys/kmem.h>
#include <sys/errno.h>

/*
 * new_def_info is used as tmp space to store new values and write them
 * to nvram.  orig_def_info gets filled with the original nvram values,
 * gets written to disk, and later used by cprboot to restore the
 * original nvram values.
 */
static cdef_t *new_def_info;

static cdef_t orig_def_info = {
	0, 0,
	0, "boot-file",    "",		/* props[0] */
	0, "boot-device",  "",		/* props[1] */
	0, "auto-boot?",   "",		/* props[2] */
	0, "diag-file",    "",		/* props[3] */
	0, "diag-device",  "",		/* props[4] */
};

/*
 * since the above array is the only place where cprop_t content
 * is specified, these defines are provided for quick/direct access.
 */
#define	CPR_BF_IDX	0		/* index for boot-file */
#define	CPR_BD_IDX	1		/* index for boot-device */
#define	CPR_AB_IDX	2		/* index for auto-boot? */
#define	CPR_DF_IDX	3		/* index for diag-file */
#define	CPR_DD_IDX	4		/* index for diag-device */

#define	CPR_PROP_PTR(dfp, idx)	&(dfp)->props[idx]


static char *cpr_next_component(char **);
static char *cpr_get_prefix(char *);
static char *cpr_build_nodename(pnode_t);
static void cpr_abbreviate_devpath(char *, char *);
static int cpr_show_props = 0;


static int
cpr_get_options_node(pnode_t *nodep)
{
	*nodep = prom_optionsnode();
	if (*nodep == OBP_NONODE || *nodep == OBP_BADNODE) {
		cpr_err(CE_WARN, "cannot get \"options\" node");
		return (ENOENT);
	}

	return (0);
}


/*
 * returns non-zero on error, otherwise returns 0 and
 * sets the result code based on (prop value == "true")
 */
static int
cpr_get_bool_prop(char *name, int *result)
{
	char value[PROP_BOOL_LEN];
	pnode_t node;
	int len, err;

	if (err = cpr_get_options_node(&node))
		return (err);
	len = prom_getproplen(node, name);
	if (len < 0 || len >= sizeof (value))
		return (ENXIO);
	bzero(value, sizeof (value));
	if (prom_getprop(node, name, value) != len)
		return (ENOENT);
	*result = (strcmp(value, "true") == 0);
	return (0);
}


/*
 * write new or original values to nvram
 */
int
cpr_update_nvram(cprop_t *props)
{
	cprop_t *tail;
	pnode_t node;
	int len, rc;

	if (rc = cpr_get_options_node(&node))
		return (rc);

	if (cpr_show_props)
		prom_printf("\ncpr_show_props:\n");
	for (tail = props + CPR_MAXPROP; props < tail; props++) {
		if (cpr_show_props) {
			prom_printf("mod=%c, name \"%s\",\tvalue \"%s\"\n",
			    props->mod, props->name, props->value);
		}
		if (props->mod == PROP_NOMOD)
			continue;
		/*
		 * Note: When doing a prom_setprop you must include the
		 * trailing NULL in the length argument, but when calling
		 * prom_getproplen() the NULL is excluded from the count!
		 */
		len = strlen(props->value);
		rc = prom_setprop(node, props->name, props->value, len + 1);
		if (rc < 0 || prom_getproplen(node, props->name) != len) {
			cpr_err(CE_WARN, "cannot set nvram \"%s\" to \"%s\"",
			    props->name, props->value);
			return (ENXIO);
		}
	}

	return (0);
}


/*
 * update nvram with the new or original nvram values;
 * this routine provides local access to both sets
 */
int
cpr_set_properties(int new)
{
	cprop_t *props;

	props = new ? new_def_info->props : orig_def_info.props;
	return (cpr_update_nvram(props));
}



/*
 * update the .mod field in both new_def_info and orig_def_info;
 * this tells cpr and cprboot which properties to set/reset.
 * then copy the arg str into a new property value at index
 */
static void
cpr_prop_update(int index, char *str)
{
	cprop_t *prop;

	prop = CPR_PROP_PTR(&orig_def_info, index);
	prop->mod = PROP_MOD;

	prop = CPR_PROP_PTR(new_def_info, index);
	prop->mod = PROP_MOD;
	(void) strcpy(prop->value, str);
}


/*
 * setup new property values within new_def_info;
 * these are used later to udpate nvram
 */
static int
cpr_prop_setup(void)
{
	int len, err, ds_ival, dev_idx, file_idx;
	char bootdev[OBP_MAXPATHLEN], bootfile[OBP_MAXPATHLEN];
	char *cp, *sp;

	/*
	 * create a new boot-device value.  for some older prom revs,
	 * a fully qualified device path can be truncated when stored
	 * to nvram.  this call generates the shortest equivalent.
	 * using devaliases could be simpler in most cases.
	 */
	cpr_abbreviate_devpath(prom_bootpath(), bootdev);

	/*
	 * create a new boot-file value; flags get appended when
	 * not reusable and when the statefile is a block device
	 */
	(void) strcpy(bootfile, CPRBOOT);
	if (!cpr_reusable_mode && cpr_statefile_is_spec())
		sp = " -S ";
	else
		sp = NULL;
	if (sp) {
		(void) strcat(bootfile, sp);
		len = strlen(bootfile);
		sp = cpr_get_statefile_prom_path();
		cpr_abbreviate_devpath(sp, &bootfile[len]);
	}

	/*
	 * record property info for booting with cprboot based on
	 * the value of diag-switch?.  when "false", set boot-device
	 * and boot-file; when "true", set diag-device and diag-file
	 */
	if (err = cpr_get_bool_prop("diag-switch?", &ds_ival))
		return (err);
	else if (ds_ival == 0) {
		dev_idx  = CPR_BD_IDX;
		file_idx = CPR_BF_IDX;
	} else {
		dev_idx  = CPR_DD_IDX;
		file_idx = CPR_DF_IDX;
	}
	cpr_prop_update(dev_idx,  bootdev);

	if (!cpr_reusable_mode)
		cpr_prop_update(file_idx, bootfile);

	/*
	 * check/set auto-boot?
	 */
	sp = orig_def_info.props[CPR_AB_IDX].value;
	cp = "true";
	if (strcmp(sp, cp))
		cpr_prop_update(CPR_AB_IDX, cp);

	return (0);
}


/*
 * setup the original and new sets of property names/values
 */
int
cpr_default_setup(int alloc)
{
	cprop_t *orig, *new, *tail;
	int len, err = 0;
	pnode_t node;
	char *fmt;

	if (alloc == 0) {
		ASSERT(new_def_info);
		kmem_free(new_def_info, sizeof (*new_def_info));
		new_def_info = NULL;
		return (0);
	}

	if (err = cpr_get_options_node(&node))
		return (err);

	/*
	 * allocate space for new properties, get the original nvram
	 * property values, mark both property sets with PROP_NOMOD,
	 * and copy the original prop names to the new set.
	 */
	ASSERT(new_def_info == NULL);
	new_def_info = kmem_zalloc(sizeof (*new_def_info), KM_SLEEP);
	new = new_def_info->props;

	for (orig = orig_def_info.props, tail = orig + CPR_MAXPROP;
	    orig < tail; orig++, new++) {
		len = prom_getproplen(node, orig->name);
		if (len < 0 || len >= (int)sizeof (orig->value)) {
			fmt = "invalid property or length for \"%s\"";
			err = ENXIO;
			break;
		}
		bzero(orig->value, sizeof (orig->value));
		if (prom_getprop(node, orig->name, orig->value) < 0) {
			fmt = "cannot get \"%s\" value";
			err = ENXIO;
			break;
		}

		new->mod = orig->mod = PROP_NOMOD;
		(void) strcpy(new->name, orig->name);
	}

	if (err) {
		kmem_free(new_def_info, sizeof (*new_def_info));
		new_def_info = NULL;
		cpr_err(CE_WARN, fmt, orig->name);
	} else
		err = cpr_prop_setup();

	return (err);
}


int
cpr_validate_definfo(int reusable)
{
	orig_def_info.mini.magic = CPR->c_cprboot_magic = CPR_DEFAULT_MAGIC;
	orig_def_info.mini.reusable = reusable;
	return (cpr_write_deffile(&orig_def_info));
}


void
cpr_send_notice(void)
{
	static char cstr[] = "\014" "\033[1P" "\033[18;21H";

	prom_printf(cstr);
	prom_printf("Saving System State. Please Wait... ");
}

void
cpr_spinning_bar(void)
{
	static char *spin_strings[] = { "|\b", "/\b", "-\b", "\\\b" };
	static int idx;

	prom_printf(spin_strings[idx]);
	if (++idx == 4)
		idx = 0;
}

void
cpr_resume_notice(void)
{
	static char cstr[] = "\014" "\033[1P" "\033[18;21H";

	prom_printf(cstr);
	prom_printf("Restoring System State. Please Wait... ");
}

/*
 * Convert a full device path to its shortest unambiguous equivalent.
 * For example, a path which starts out /iommu@x,y/sbus@i,j/espdma . . .
 * might be converted to /iommu/sbus/espdma . . .  If we encounter
 * problems at any point, just output the unabbreviated path.
 */
static void
cpr_abbreviate_devpath(char *in_path, char *out_path)
{
	static pnode_t cur_node;
	char *position = in_path + 1;	/* Skip the leading slash. */
	char *cmpt;

	cur_node = prom_nextnode(0);
	*out_path = '\0';

	while ((cmpt = cpr_next_component(&position)) != NULL) {
		pnode_t long_match = 0;
		pnode_t short_match = 0;
		int short_hits = 0;
		char *name;
		char *prefix = cpr_get_prefix(cmpt);

		/* Go to next tree level by getting first child. */
		if ((cur_node = prom_childnode(cur_node)) == 0) {
			(void) strcpy(out_path, in_path);
			return;
		}

		/*
		 * Traverse the current level and remember the node (if any)
		 * where we match on the fully qualified component name.
		 * Also remember the node of the most recent prefix match
		 * and the number of such matches.
		 */
		do {
			name = cpr_build_nodename(cur_node);
			if (strcmp(name, cmpt) == 0)
				long_match = cur_node;
			if (strncmp(prefix, name, strlen(prefix)) == 0) {
				short_match = cur_node;
				short_hits++;
			}
		} while ((cur_node = prom_nextnode(cur_node)) != 0);

		/*
		 * We don't want to be too dependent on what we know
		 * about how the names are stored.  We just assume that
		 * if there is only one match on the prefix, we can
		 * use it, otherwise we need to use a fully qualified
		 * name.  In the "impossible" cases we just give up
		 * and use the complete input devpath.
		 */
		(void) strcat(out_path, "/");
		if (short_hits == 1) {
			(void) strcat(out_path, prefix);
			cur_node = short_match;
		}
		else
			if (long_match) {
				(void) strcat(out_path, cmpt);
				cur_node = long_match;
			} else {
				(void) strcpy(out_path, in_path);
				return;
			}
	}
	/* We need to copy the target and slice info manually. */
	(void) strcat(out_path, strrchr(in_path, '@'));
}

/*
 * Return a pointer to the next component of a device path or NULL if
 * the entire path has been consumed.  Note that we update the caller's
 * pointer to the current position in the full pathname buffer.
 */
static char *
cpr_next_component(char **path)
{
	static char obuf[64];
	char *slash;
	int len = strlen(*path);

	if (len == 0)
		return (NULL);

	if ((slash = strchr(*path, '/'))) {
		len = slash - *path;
		(void) strncpy(obuf, *path, len);
		obuf[len] = '\0';
		*path += len + 1;	/* Position beyond the slash. */
	} else {
		(void) strcpy(obuf, *path);
		*path += len;		/* Position at the terminal NULL. */
	}

	return (obuf);
}

/*
 * Return a pointer to the prefix (i.e., the basic unqualified node name)
 * Basically, this is the part of the fully qualified name before the @.
 */
static char *
cpr_get_prefix(char *cmpt)
{
	static char	prefix[OBP_MAXDRVNAME];
	char		*at_sign = strchr(cmpt, '@');
	int		len = at_sign ? at_sign - cmpt : strlen(cmpt);

	(void) strncpy(prefix, cmpt, len);
	prefix[len] = '\0';

	return (prefix);
}

/*
 * Build the unambiguous name for the current node, like iommu@f,e10000000.
 * The prefix is just the "name" property, and the qualifier is constructed
 * from the first two (binary) words of the "reg" property.
 */
static char *
cpr_build_nodename(pnode_t node)
{
	static char	name[OBP_MAXPATHLEN];
	int		reg[512];
	char		buf[32]; /* must contain expansion of @%x,%x */
	int		prop_len = prom_getproplen(node, OBP_NAME);

	if (prop_len < 0 || prop_len >= sizeof (name) ||
	    prom_getprop(node, OBP_NAME, name) < 0)
		return ("");
	name[prop_len] = '\0';

	if ((prop_len = prom_getproplen(node, OBP_REG)) <
	    2 * sizeof (int) || prop_len >= sizeof (reg))
		return (name);

	if (prom_getprop(node, OBP_REG, (caddr_t)reg) < 0)
		return (name);

	(void) sprintf(buf, "@%x,%x", reg[0], reg[1]);
	(void) strcat(name, buf);

	return (name);
}

/*
 * Makes a printable list of prom_prop names for error messages
 * Caller must free space.
 */
char *
cpr_enumerate_promprops(char **bufp, size_t *len)
{
	cprop_t *prop, *tail;
	size_t size = 2;	/* for "." */
	char *buf;

	tail = &orig_def_info.props[CPR_MAXPROP];
	for (prop = orig_def_info.props; prop < tail; prop++)
		size += strlen(prop->name) + 2;	/* + ", " */

	buf = kmem_alloc(size, KM_SLEEP);
	*buf = '\0';

	for (prop = orig_def_info.props; prop < tail; prop++) {
		if (strlen(buf))
			(void) strcat(buf, ", ");
		(void) strcat(buf, prop->name);
	}
	(void) strcat(buf, ".");

	*bufp = buf;
	*len = size;
	return (buf);
}
