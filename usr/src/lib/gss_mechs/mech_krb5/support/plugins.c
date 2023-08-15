/*
 * util/support/plugins.c
 *
 * Copyright 2006 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * Plugin module support, and shims around dlopen/whatever.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include "k5-plugin.h"
#if USE_DLOPEN
#include <dlfcn.h>
#endif
#if USE_CFBUNDLE
#include <CoreFoundation/CoreFoundation.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdarg.h>
/*ARGSUSED*/
static void Tprintf (const char *fmt, ...)
{
#ifdef DEBUG
    va_list va;
    va_start (va, fmt);
    vfprintf (stderr, fmt, va);
    va_end (va);
#endif
}

struct plugin_file_handle {
#if USE_DLOPEN
    void *dlhandle;
#endif
#if USE_CFBUNDLE
    CFBundleRef bundle;
#endif
#if !defined (USE_DLOPEN) && !defined (USE_CFBUNDLE)
    char dummy;
#endif
};

/*ARGSUSED2*/
long KRB5_CALLCONV
krb5int_open_plugin (const char *filepath, struct plugin_file_handle **h, struct errinfo *ep)
{
    long err = 0;
    struct stat statbuf;
    struct plugin_file_handle *htmp = NULL;
    int got_plugin = 0;

    if (!err) {
        if (stat (filepath, &statbuf) < 0) {
            Tprintf ("stat(%s): %s\n", filepath, strerror (errno));
            err = errno;
        }
    }

    if (!err) {
        htmp = calloc (1, sizeof (*htmp)); /* calloc initializes ptrs to NULL */
        if (htmp == NULL) { err = errno; }
    }

#if USE_DLOPEN
    if (!err && (statbuf.st_mode & S_IFMT) == S_IFREG) {
        void *handle = NULL;
#ifdef RTLD_GROUP
#define PLUGIN_DLOPEN_FLAGS (RTLD_NOW | RTLD_LOCAL | RTLD_GROUP)
#else
#define PLUGIN_DLOPEN_FLAGS (RTLD_NOW | RTLD_LOCAL)
#endif

        if (!err) {
            handle = dlopen(filepath, PLUGIN_DLOPEN_FLAGS);
            if (handle == NULL) {
                const char *e = dlerror();
                Tprintf ("dlopen(%s): %s\n", filepath, e);
                err = ENOENT; /* XXX */
		krb5int_set_error (ep, err, "%s", e);
            }
        }

        if (!err) {
            got_plugin = 1;
            htmp->dlhandle = handle;
            handle = NULL;
        }

        if (handle != NULL) { dlclose (handle); }
    }
#endif

#if USE_CFBUNDLE
    if (!err && (statbuf.st_mode & S_IFMT) == S_IFDIR) {
        CFStringRef pluginPath = NULL;
        CFURLRef pluginURL = NULL;
        CFBundleRef pluginBundle = NULL;

        if (!err) {
            pluginPath = CFStringCreateWithCString (kCFAllocatorDefault, filepath,
                                                    kCFStringEncodingASCII);
            if (pluginPath == NULL) { err = ENOMEM; }
        }

        if (!err) {
            pluginURL = CFURLCreateWithFileSystemPath (kCFAllocatorDefault, pluginPath,
                                                       kCFURLPOSIXPathStyle, true);
            if (pluginURL == NULL) { err = ENOMEM; }
        }

        if (!err) {
            pluginBundle = CFBundleCreate (kCFAllocatorDefault, pluginURL);
            if (pluginBundle == NULL) { err = ENOENT; } /* XXX need better error */
        }

        if (!err) {
            if (!CFBundleIsExecutableLoaded (pluginBundle)) {
                int loaded = CFBundleLoadExecutable (pluginBundle);
                if (!loaded) { err = ENOENT; }  /* XXX need better error */
            }
        }

        if (!err) {
            got_plugin = 1;
            htmp->bundle = pluginBundle;
            pluginBundle = NULL;  /* htmp->bundle takes ownership */
        }

        if (pluginBundle != NULL) { CFRelease (pluginBundle); }
        if (pluginURL    != NULL) { CFRelease (pluginURL); }
        if (pluginPath   != NULL) { CFRelease (pluginPath); }
    }
#endif

    if (!err && !got_plugin) {
        err = ENOENT;  /* no plugin or no way to load plugins */
    }

    if (!err) {
        *h = htmp;
        htmp = NULL;  /* h takes ownership */
    }

    if (htmp != NULL) { free (htmp); }

    return err;
}

/*ARGSUSED*/
static long
krb5int_get_plugin_sym (struct plugin_file_handle *h,
                        const char *csymname, int isfunc, void **ptr,
			struct errinfo *ep)
{
    long err = 0;
    void *sym = NULL;

#if USE_DLOPEN
    if (!err && !sym && (h->dlhandle != NULL)) {
        /* XXX Do we need to add a leading "_" to the symbol name on any
        modern platforms?  */
        sym = dlsym (h->dlhandle, csymname);
        if (sym == NULL) {
            const char *e = dlerror (); /* XXX copy and save away */
            Tprintf ("dlsym(%s): %s\n", csymname, e);
            err = ENOENT; /* XXX */
	    krb5int_set_error(ep, err, "%s", e);
        }
    }
#endif

#if USE_CFBUNDLE
    if (!err && !sym && (h->bundle != NULL)) {
        CFStringRef cfsymname = NULL;

        if (!err) {
            cfsymname = CFStringCreateWithCString (kCFAllocatorDefault, csymname,
                                                   kCFStringEncodingASCII);
            if (cfsymname == NULL) { err = ENOMEM; }
        }

        if (!err) {
            if (isfunc) {
                sym = CFBundleGetFunctionPointerForName (h->bundle, cfsymname);
            } else {
                sym = CFBundleGetDataPointerForName (h->bundle, cfsymname);
            }
            if (sym == NULL) { err = ENOENT; }  /* XXX */
        }

        if (cfsymname != NULL) { CFRelease (cfsymname); }
    }
#endif

    if (!err && (sym == NULL)) {
        err = ENOENT;  /* unimplemented */
    }

    if (!err) {
        *ptr = sym;
    }

    return err;
}

long KRB5_CALLCONV
krb5int_get_plugin_data (struct plugin_file_handle *h, const char *csymname,
			 void **ptr, struct errinfo *ep)
{
    return krb5int_get_plugin_sym (h, csymname, 0, ptr, ep);
}

long KRB5_CALLCONV
krb5int_get_plugin_func (struct plugin_file_handle *h, const char *csymname,
			 void (**ptr)(), struct errinfo *ep)
{
    void *dptr = NULL;
    long err = krb5int_get_plugin_sym (h, csymname, 1, &dptr, ep);
    if (!err) {
        /* Cast function pointers to avoid code duplication */
        *ptr = (void (*)()) dptr;
    }
    return err;
}

void KRB5_CALLCONV
krb5int_close_plugin (struct plugin_file_handle *h)
{
#if USE_DLOPEN
    if (h->dlhandle != NULL) { dlclose(h->dlhandle); }
#endif
#if USE_CFBUNDLE
    /* Do not call CFBundleUnloadExecutable because it's not ref counted.
     * CFRelease will unload the bundle if the internal refcount goes to zero. */
    if (h->bundle != NULL) { CFRelease (h->bundle); }
#endif
    free (h);
}

/* autoconf docs suggest using this preference order */
#if HAVE_DIRENT_H || USE_DIRENT_H
#include <dirent.h>
#define NAMELEN(D) strlen((D)->d_name)
#else
#define dirent direct
#define NAMELEN(D) ((D)->d->namlen)
#if HAVE_SYS_NDIR_H
# include <sys/ndir.h>
#elif HAVE_SYS_DIR_H
# include <sys/dir.h>
#elif HAVE_NDIR_H
# include <ndir.h>
#endif
#endif


#ifdef HAVE_STRERROR_R
#define ERRSTR(ERR, BUF) \
    (strerror_r (ERR, BUF, sizeof(BUF)) == 0 ? BUF : strerror (ERR))
#else
#define ERRSTR(ERR, BUF) \
    (strerror (ERR))
#endif

static long
krb5int_plugin_file_handle_array_init (struct plugin_file_handle ***harray)
{
    long err = 0;

    *harray = calloc (1, sizeof (**harray)); /* calloc initializes to NULL */
    if (*harray == NULL) { err = errno; }

    return err;
}

static long
krb5int_plugin_file_handle_array_add (struct plugin_file_handle ***harray, int *count,
                                      struct plugin_file_handle *p)
{
    long err = 0;
    struct plugin_file_handle **newharray = NULL;
    int newcount = *count + 1;

    newharray = realloc (*harray, ((newcount + 1) * sizeof (**harray))); /* +1 for NULL */
    if (newharray == NULL) {
        err = errno;
    } else {
        newharray[newcount - 1] = p;
        newharray[newcount] = NULL;
	*count = newcount;
        *harray = newharray;
    }

    return err;
}

static void
krb5int_plugin_file_handle_array_free (struct plugin_file_handle **harray)
{
    if (harray != NULL) {
        int i;
        for (i = 0; harray[i] != NULL; i++) {
            krb5int_close_plugin (harray[i]);
        }
        free (harray);
    }
}

#if TARGET_OS_MAC
#define FILEEXTS { "", ".bundle", ".so", NULL }
#elif defined(_WIN32)
#define FILEEXTS  { "", ".dll", NULL }
#else
#define FILEEXTS  { "", ".so", NULL }
#endif


static void
krb5int_free_plugin_filenames (char **filenames)
{
    if (filenames != NULL) {
        int i;
        for (i = 0; filenames[i] != NULL; i++) {
            free (filenames[i]);
        }
        free (filenames);
    }
}


static long
krb5int_get_plugin_filenames (const char * const *filebases, char ***filenames)
{
    long err = 0;
    static const char *const fileexts[] = FILEEXTS;
    char **tempnames = NULL;
    int i;

    if (!err) {
        size_t count = 0;
        for (i = 0; filebases[i] != NULL; i++, count++);
        for (i = 0; fileexts[i] != NULL; i++, count++);
        tempnames = calloc (count, sizeof (char *));
        if (tempnames == NULL) { err = errno; }
    }

    if (!err) {
        int j;
        for (i = 0; !err && (filebases[i] != NULL); i++) {
            size_t baselen = strlen (filebases[i]);
            for (j = 0; !err && (fileexts[j] != NULL); j++) {
                size_t len = baselen + strlen (fileexts[j]) + 2; /* '.' + NULL */
                tempnames[i+j] = malloc (len * sizeof (char));
                if (tempnames[i+j] == NULL) {
                    err = errno;
                } else {
		    /*LINTED*/
                    sprintf (tempnames[i+j], "%s%s", filebases[i], fileexts[j]);
                }
            }
        }
    }

    if (!err) {
        *filenames = tempnames;
        tempnames = NULL;
    }

    if (tempnames != NULL) { krb5int_free_plugin_filenames (tempnames); }

    return err;
}


/* Takes a NULL-terminated list of directories.  If filebases is NULL, filebases is ignored
 * all plugins in the directories are loaded.  If filebases is a NULL-terminated array of names,
 * only plugins in the directories with those name (plus any platform extension) are loaded. */

long KRB5_CALLCONV
krb5int_open_plugin_dirs (const char * const *dirnames,
                          const char * const *filebases,
			  struct plugin_dir_handle *dirhandle,
                          struct errinfo *ep)
{
    long err = 0;
    struct plugin_file_handle **h = NULL;
    int count = 0;
    char **filenames = NULL;
    int i;

    if (!err) {
        err = krb5int_plugin_file_handle_array_init (&h);
    }

    if (!err && (filebases != NULL)) {
	err = krb5int_get_plugin_filenames (filebases, &filenames);
    }

    for (i = 0; !err && dirnames[i] != NULL; i++) {
	size_t dirnamelen = strlen (dirnames[i]) + 1; /* '/' */
        if (filenames != NULL) {
            /* load plugins with names from filenames from each directory */
            int j;

            for (j = 0; !err && filenames[j] != NULL; j++) {
                struct plugin_file_handle *handle = NULL;
		char *filepath = NULL;

		if (!err) {
		    filepath = malloc (dirnamelen + strlen (filenames[j]) + 1); /* NULL */
		    if (filepath == NULL) {
			err = errno;
		    } else {
			/*LINTED*/
			sprintf (filepath, "%s/%s", dirnames[i], filenames[j]);
		    }
		}

                if (krb5int_open_plugin (filepath, &handle, ep) == 0) {
                    err = krb5int_plugin_file_handle_array_add (&h, &count, handle);
                    if (!err) { handle = NULL; }  /* h takes ownership */
                }

		if (filepath != NULL) { free (filepath); }
		if (handle   != NULL) { krb5int_close_plugin (handle); }
            }
        } else {
            /* load all plugins in each directory */
#ifndef _WIN32
	    DIR *dir = opendir (dirnames[i]);

            while (dir != NULL && !err) {
                struct dirent *d = NULL;
                char *filepath = NULL;
                struct plugin_file_handle *handle = NULL;
                int len;

                d = readdir (dir);
                if (d == NULL) { break; }

                if ((strcmp (d->d_name, ".") == 0) ||
                    (strcmp (d->d_name, "..") == 0)) {
                    continue;
                }

		/* Solaris Kerberos: Only open files with a .so extension */
		len = NAMELEN (d);
		if (len < 3 || strcmp(".so", d->d_name + len - 3 ) != 0)
			continue;

		if (!err) {
		    filepath = malloc (dirnamelen + len + 1); /* NULL */
		    if (filepath == NULL) {
			err = errno;
		    } else {
			/*LINTED*/
			sprintf (filepath, "%s/%*s", dirnames[i], len, d->d_name);
		    }
		}

                if (!err) {
                    if (krb5int_open_plugin (filepath, &handle, ep) == 0) {
                        err = krb5int_plugin_file_handle_array_add (&h, &count, handle);
                        if (!err) { handle = NULL; }  /* h takes ownership */
                    }
                }

                if (filepath  != NULL) { free (filepath); }
                if (handle    != NULL) { krb5int_close_plugin (handle); }
            }

            if (dir != NULL) { closedir (dir); }
#else
	    /* Until a Windows implementation of this code is implemented */
	    err = ENOENT;
#endif /* _WIN32 */
        }
    }

    if (err == ENOENT) {
        err = 0;  /* ran out of plugins -- do nothing */
    }

    if (!err) {
        dirhandle->files = h;
        h = NULL;  /* dirhandle->files takes ownership */
    }

    if (filenames != NULL) { krb5int_free_plugin_filenames (filenames); }
    if (h         != NULL) { krb5int_plugin_file_handle_array_free (h); }

    return err;
}

void KRB5_CALLCONV
krb5int_close_plugin_dirs (struct plugin_dir_handle *dirhandle)
{
    if (dirhandle->files != NULL) {
        int i;
        for (i = 0; dirhandle->files[i] != NULL; i++) {
            krb5int_close_plugin (dirhandle->files[i]);
        }
        free (dirhandle->files);
        dirhandle->files = NULL;
    }
}

void KRB5_CALLCONV
krb5int_free_plugin_dir_data (void **ptrs)
{
    /* Nothing special to be done per pointer.  */
    free(ptrs);
}

long KRB5_CALLCONV
krb5int_get_plugin_dir_data (struct plugin_dir_handle *dirhandle,
			     const char *symname,
			     void ***ptrs,
			     struct errinfo *ep)
{
    long err = 0;
    void **p = NULL;
    int count = 0;

    /* XXX Do we need to add a leading "_" to the symbol name on any
       modern platforms?  */

    Tprintf("get_plugin_data_sym(%s)\n", symname);

    if (!err) {
        p = calloc (1, sizeof (*p)); /* calloc initializes to NULL */
        if (p == NULL) { err = errno; }
    }

    if (!err && (dirhandle != NULL) && (dirhandle->files != NULL)) {
        int i = 0;

        for (i = 0; !err && (dirhandle->files[i] != NULL); i++) {
            void *sym = NULL;

            if (krb5int_get_plugin_data (dirhandle->files[i], symname, &sym, ep) == 0) {
                void **newp = NULL;

                count++;
                newp = realloc (p, ((count + 1) * sizeof (*p))); /* +1 for NULL */
                if (newp == NULL) {
                    err = errno;
                } else {
                    p = newp;
                    p[count - 1] = sym;
                    p[count] = NULL;
                }
            }
        }
    }

    if (!err) {
        *ptrs = p;
        p = NULL; /* ptrs takes ownership */
    }

    if (p != NULL) { free (p); }

    return err;
}

void KRB5_CALLCONV
krb5int_free_plugin_dir_func (void (**ptrs)(void))
{
    /* Nothing special to be done per pointer.  */
    free(ptrs);
}

long KRB5_CALLCONV
krb5int_get_plugin_dir_func (struct plugin_dir_handle *dirhandle,
			     const char *symname,
			     void (***ptrs)(void),
			     struct errinfo *ep)
{
    long err = 0;
    void (**p)() = NULL;
    int count = 0;

    /* XXX Do we need to add a leading "_" to the symbol name on any
        modern platforms?  */

    Tprintf("get_plugin_data_sym(%s)\n", symname);

    if (!err) {
        p = calloc (1, sizeof (*p)); /* calloc initializes to NULL */
        if (p == NULL) { err = errno; }
    }

    if (!err && (dirhandle != NULL) && (dirhandle->files != NULL)) {
        int i = 0;

        for (i = 0; !err && (dirhandle->files[i] != NULL); i++) {
            void (*sym)() = NULL;

            if (krb5int_get_plugin_func (dirhandle->files[i], symname, &sym, ep) == 0) {
                void (**newp)() = NULL;

                count++;
                newp = realloc (p, ((count + 1) * sizeof (*p))); /* +1 for NULL */
                if (newp == NULL) {
                    err = errno;
                } else {
                    p = newp;
                    p[count - 1] = sym;
                    p[count] = NULL;
                }
            }
        }
    }

    if (!err) {
        *ptrs = p;
        p = NULL; /* ptrs takes ownership */
    }

    if (p != NULL) { free (p); }

    return err;
}
