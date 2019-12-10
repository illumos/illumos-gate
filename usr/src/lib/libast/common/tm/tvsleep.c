/***********************************************************************
 *                                                                      *
 *               This software is part of the ast package               *
 *          Copyright (c) 1985-2013 AT&T Intellectual Property          *
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
 *               Glenn Fowler <glenn.s.fowler@gmail.com>                *
 *                    David Korn <dgkorn@gmail.com>                     *
 *                     Phong Vo <phongvo@gmail.com>                     *
 *                                                                      *
 ***********************************************************************/

#include <errno.h>
#include <time.h>

#include "tv.h"

/*
 * sleep for tv
 * non-zero exit if sleep did not complete
 * with remaining time in rv
 *
 * NOTE: some systems hide nanosleep() ouside of -lc -- puleeze
 */

int tvsleep(const Tv_t *tv, Tv_t *rv) {
    struct timespec stv;
    struct timespec srv;
    int r;

    stv.tv_sec = tv->tv_sec;
    stv.tv_nsec = tv->tv_nsec;
    if ((r = nanosleep(&stv, &srv)) && errno == EINTR && rv) {
        rv->tv_sec = srv.tv_sec;
        rv->tv_nsec = srv.tv_nsec;
    }
    return r;
}
