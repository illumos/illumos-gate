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
 * Copyright 2004 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */


#include <stdlib.h>
#include <string.h>

#include <vroot/vroot.h>
#include <vroot/args.h>

#include <string.h>
#include <sys/param.h>
#include <sys/file.h>

typedef struct {
	short		init;
	pathpt		vector;
	const char	*env_var;
} vroot_patht;

typedef struct {
	vroot_patht	vroot;
	vroot_patht	path;
	char		full_path[MAXPATHLEN+1];
	char		*vroot_start;
	char		*path_start;
	char		*filename_start;
	int		scan_vroot_first;
	int		cpp_style_path;
} vroot_datat, *vroot_datapt;

static vroot_datat	vroot_data= {
	{ 0, NULL, "VIRTUAL_ROOT"},
	{ 0, NULL, "PATH"},
	"", NULL, NULL, NULL, 0, 1};

void
add_dir_to_path(const char *path, register pathpt *pointer, register int position)
{
	register int		size= 0;
	register int		length;
	register char		*name;
	register pathcellpt	p;
	pathpt			new_path;

	if (*pointer != NULL) {
		for (p= &((*pointer)[0]); p->path != NULL; p++, size++);
		if (position < 0)
			position= size;}
	else
		if (position < 0)
			position= 0;
	if (position >= size) {
		new_path= (pathpt)calloc((unsigned)(position+2), sizeof(pathcellt));
		if (*pointer != NULL) {
			memcpy((char *)new_path,(char *)(*pointer),  size*sizeof(pathcellt));
			free((char *)(*pointer));};
		*pointer= new_path;};
	length= strlen(path);
	name= (char *)malloc((unsigned)(length+1));
	(void)strcpy(name, path);
	if ((*pointer)[position].path != NULL)
		free((*pointer)[position].path);
	(*pointer)[position].path= name;
	(*pointer)[position].length= length;
}

pathpt
parse_path_string(register char *string, register int remove_slash)
{
	register char		*p;
	pathpt			result= NULL;

	if (string != NULL)
		for (; 1; string= p+1) {
			if (p= strchr(string, ':')) *p= 0;
			if ((remove_slash == 1) && !strcmp(string, "/"))
				add_dir_to_path("", &result, -1);
			else
				add_dir_to_path(string, &result, -1);
			if (p) *p= ':';
			else return(result);};
	return((pathpt)NULL);
}

const char *
get_vroot_name(void)
{
	return(vroot_data.vroot.env_var);
}

const char *
get_path_name(void)
{
	return(vroot_data.path.env_var);
}

void
flush_path_cache(void)
{
	vroot_data.path.init= 0;
}

void
flush_vroot_cache(void)
{
	vroot_data.vroot.init= 0;
}

void
scan_path_first(void)
{
	vroot_data.scan_vroot_first= 0;
}

void
scan_vroot_first(void)
{
	vroot_data.scan_vroot_first= 1;
}

void
set_path_style(int style)
{
	vroot_data.cpp_style_path= style;
}

char *
get_vroot_path(register char **vroot, register char **path, register char **filename)
{
	if (vroot != NULL) {
		if ((*vroot= vroot_data.vroot_start) == NULL)
		if ((*vroot= vroot_data.path_start) == NULL)
		*vroot= vroot_data.filename_start;};
	if (path != NULL) {
		if ((*path= vroot_data.path_start) == NULL)
		*path= vroot_data.filename_start;};
	if (filename != NULL)
		*filename= vroot_data.filename_start;
	return(vroot_data.full_path);
}

void
translate_with_thunk(register char *filename, int (*thunk) (char *), pathpt path_vector, pathpt vroot_vector, rwt rw)
{
	register pathcellt	*vp;
	pathcellt		*pp;
	register pathcellt	*pp1;
	register char		*p;
	int			flags[256];

/* Setup path to use */
	if (rw == rw_write)
		pp1= NULL;		/* Do not use path when writing */
	else {
		if (path_vector == VROOT_DEFAULT) {
			if (!vroot_data.path.init) {
				vroot_data.path.init= 1;
				vroot_data.path.vector= parse_path_string(getenv(vroot_data.path.env_var), 0);};
			path_vector= vroot_data.path.vector;};
		pp1= path_vector == NULL ? NULL : &(path_vector)[0];};

/* Setup vroot to use */
	if (vroot_vector == VROOT_DEFAULT) {
		if (!vroot_data.vroot.init) {
			vroot_data.vroot.init= 1;
			vroot_data.vroot.vector= parse_path_string(getenv(vroot_data.vroot.env_var), 1);};
		vroot_vector= vroot_data.vroot.vector;};
	vp= vroot_vector == NULL ? NULL : &(vroot_vector)[0];

/* Setup to remember pieces */
	vroot_data.vroot_start= NULL;
	vroot_data.path_start= NULL;
	vroot_data.filename_start= NULL;

	int flen = strlen(filename);
	if(flen >= MAXPATHLEN) {
		errno = ENAMETOOLONG;
		return;
	}

	switch ((vp ?1:0) + (pp1 ? 2:0)) {
	    case 0:	/* No path. No vroot. */
	    use_name:
		(void)strcpy(vroot_data.full_path, filename);
		vroot_data.filename_start= vroot_data.full_path;
		(void)(*thunk)(vroot_data.full_path);
		return;
	    case 1:	/* No path. Vroot */
		if (filename[0] != '/') goto use_name;
		for (; vp->path != NULL; vp++) {
			if((1 + flen + vp->length) >= MAXPATHLEN) {
				errno = ENAMETOOLONG;
				continue;
			}
			p= vroot_data.full_path;
			(void)strcpy(vroot_data.vroot_start= p, vp->path);
			p+= vp->length;
			(void)strcpy(vroot_data.filename_start= p, filename);
			if ((*thunk)(vroot_data.full_path)) return;};
		(void)strcpy(vroot_data.full_path, filename);
		return;
	    case 2:	/* Path. No vroot. */
		if (vroot_data.cpp_style_path) {
			if (filename[0] == '/') goto use_name;
		} else {
			if (strchr(filename, '/') != NULL) goto use_name;
		};
		for (; pp1->path != NULL; pp1++) {
			p= vroot_data.full_path;
			if((1 + flen + pp1->length) >= MAXPATHLEN) {
				errno = ENAMETOOLONG;
				continue;
			}
			if (vroot_data.cpp_style_path) {
				(void)strcpy(vroot_data.path_start= p, pp1->path);
				p+= pp1->length;
				*p++= '/';
			} else {
				if (pp1->length != 0) {
					(void)strcpy(vroot_data.path_start= p,
					    pp1->path);
					p+= pp1->length;
					*p++= '/';
				};
			};
			(void)strcpy(vroot_data.filename_start= p, filename);
			if ((*thunk)(vroot_data.full_path)) return;};
		(void)strcpy(vroot_data.full_path, filename);
		return;
	    case 3: {	/* Path. Vroot. */
			int *rel_path, path_len= 1;
		if (vroot_data.scan_vroot_first == 0) {
			for (pp= pp1; pp->path != NULL; pp++) path_len++;
			rel_path= flags;
			for (path_len-= 2; path_len >= 0; path_len--) rel_path[path_len]= 0;
			for (; vp->path != NULL; vp++)
				for (pp= pp1, path_len= 0; pp->path != NULL; pp++, path_len++) {
					int len = 0;
					if (rel_path[path_len] == 1) continue;
					if (pp->path[0] != '/') rel_path[path_len]= 1;
					p= vroot_data.full_path;
					if ((filename[0] == '/') || (pp->path[0] == '/')) {
						if(vp->length >= MAXPATHLEN) {
							errno = ENAMETOOLONG;
							continue;
						}
						(void)strcpy(vroot_data.vroot_start= p, vp->path); p+= vp->length;
						len += vp->length;
					};
					if (vroot_data.cpp_style_path) {
						if (filename[0] != '/') {
							if(1 + len + pp->length >= MAXPATHLEN) {
								errno = ENAMETOOLONG;
								continue;
							}
							(void)strcpy(vroot_data.path_start= p, pp->path); p+= pp->length;
							*p++= '/';
							len += 1 + pp->length;
						};
					} else {
						if (strchr(filename, '/') == NULL) {
							if (pp->length != 0) {
								if(1 + len + pp->length >= MAXPATHLEN) {
									errno = ENAMETOOLONG;
									continue;
								}
								(void)strcpy(vroot_data.path_start= p,
								    pp->path);
								p+= pp->length;
								*p++= '/';
								len += 1 + pp->length;
							}
						}
					};
					(void)strcpy(vroot_data.filename_start= p, filename);
					if ((*thunk)(vroot_data.full_path)) return;};}
		else { pathcellt *vp1= vp;
			for (pp= pp1, path_len= 0; pp->path != NULL; pp++, path_len++)
				for (vp= vp1; vp->path != NULL; vp++) {
					int len = 0;
					p= vroot_data.full_path;
					if ((filename[0] == '/') || (pp->path[0] == '/')) {
						if(vp->length >= MAXPATHLEN) {
							errno = ENAMETOOLONG;
							continue;
						}
						(void)strcpy(vroot_data.vroot_start= p, vp->path); p+= vp->length;
						len += vp->length;
					}
					if (vroot_data.cpp_style_path) {
						if (filename[0] != '/') {
							if(1 + len + pp->length >= MAXPATHLEN) {
								errno = ENAMETOOLONG;
								continue;
							}
							(void)strcpy(vroot_data.path_start= p, pp->path); p+= pp->length;
							*p++= '/';
							len += 1 + pp->length;
						}
					} else {
						if (strchr(filename, '/') == NULL) {
							if(1 + len + pp->length >= MAXPATHLEN) {
								errno = ENAMETOOLONG;
								continue;
							}
							(void)strcpy(vroot_data.path_start= p, pp->path); p+= pp->length;
							*p++= '/';
							len += 1 + pp->length;
						}
					}
					(void)strcpy(vroot_data.filename_start= p, filename);
					if ((*thunk)(vroot_data.full_path)) return;};};
		(void)strcpy(vroot_data.full_path, filename);
		return;};};
}
