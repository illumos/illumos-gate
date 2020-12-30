/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1997-2012 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 */

#include "dlllib.h"

typedef void* (*Dll_lib_f)(const char*, void*, const char*);

typedef struct Dll_lib_s
{
	struct Dll_lib_s*	next;
	Dll_lib_f		libf;
	char*			path;
	char			base[1];
} Dll_lib_t;

/*
 * split <name,base,type,opts> from name into names
 */

Dllnames_t*
dllnames(const char* id, const char* name, Dllnames_t* names)
{
	char*	s;
	char*	t;
	char*	b;
	char*	e;
	size_t	n;

	n = strlen(id);
	if (strneq(name, id, n) && (streq(name + n, "_s") || streq(name + n, "_t")))
		return 0;
	if (!names)
	{
		s = fmtbuf(sizeof(Dllnames_t*) + sizeof(names) - 1);
		if (n = (s - (char*)0) % sizeof(names))
			s += sizeof(names) - n;
		names = (Dllnames_t*)s;
	}

	/*
	 * determine the base name
	 */

	if ((s = strrchr(name, '/')) || (s = strrchr(name, '\\')))
		s++;
	else
		s = (char*)name;
	if (strneq(s, "lib", 3))
		s += 3;
	b = names->base = names->data;
	e = b + sizeof(names->data) - 1;
	t = s;
	while (b < e && *t && *t != '.' && *t != '-' && *t != ':')
		*b++ = *t++;
	*b++ = 0;

	/*
	 * determine the optional type
	 */

	if (t = strrchr(s, ':'))
	{
		names->name = b;
		while (b < e && s < t)
			*b++ = *s++;
		*b++ = 0;
		names->type = b;
		while (b < e && *++t)
			*b++ = *t;
		*b++ = 0;
	}
	else
	{
		names->name = (char*)name;
		names->type = 0;
	}
	*(names->path = b) = 0;
	names->opts = 0;
	names->id = (char*)id;
	return names;
}

/*
 * return method pointer for <id,version> in names
 */

void*
dll_lib(Dllnames_t* names, unsigned long version, Dllerror_f dllerrorf, void* disc)
{
	void*			dll;
	Dll_lib_t*		lib;
	Dll_lib_f		libf;
	ssize_t			n;
	char			sym[64];

	static Dll_lib_t*	loaded;

	if (!names)
		return 0;

	/*
	 * check if plugin already loaded
	 */

	for (lib = loaded; lib; lib = lib->next)
		if (streq(names->base, lib->base))
		{
			libf = lib->libf;
			goto init;
		}

	/*
	 * load
	 */

	if (!(dll = dllplugin(names->id, names->name, NiL, version, NiL, RTLD_LAZY, names->path, names->data + sizeof(names->data) - names->path)) && (streq(names->name, names->base) || !(dll = dllplugin(names->id, names->base, NiL, version, NiL, RTLD_LAZY, names->path, names->data + sizeof(names->data) - names->path))))
	{
		if (dllerrorf)
			(*dllerrorf)(NiL, disc, 2, "%s: library not found", names->name);
		else
			errorf("dll", NiL, -1, "dll_lib: %s version %lu library not found", names->name, version);
		return 0;
	}

	/*
	 * init
	 */

	sfsprintf(sym, sizeof(sym), "%s_lib", names->id);
	if (!(libf = (Dll_lib_f)dlllook(dll, sym)))
	{
		if (dllerrorf)
			(*dllerrorf)(NiL, disc, 2, "%s: %s: initialization function not found in library", names->path, sym);
		else
			errorf("dll", NiL, -1, "dll_lib: %s version %lu initialization function %s not found in library", names->name, version, sym);
		return 0;
	}

	/*
	 * add to the loaded list
	 */

	if (lib = newof(0, Dll_lib_t, 1, (n = strlen(names->base)) + strlen(names->path) + 1))
	{
		lib->libf = libf;
		strcpy(lib->base, names->base);
		strcpy(lib->path = lib->base + n + 1, names->path);
		lib->next = loaded;
		loaded = lib;
		errorf("dll", NiL, -1, "dll_lib: %s version %lu loaded from %s", names->name, version, lib->path);
	}
 init:
	return (*libf)(names->path, disc, names->type);
}

/*
 * return method pointer for <id,name,version>
 */

void*
dllmeth(const char* id, const char* name, unsigned long version)
{
	Dllnames_t	names;

	return dll_lib(dllnames(id, name, &names), version, 0, 0);
}
