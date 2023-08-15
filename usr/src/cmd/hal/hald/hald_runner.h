/***************************************************************************
 *
 * CVSID: $Id$
 *
 * hald_runner.h - Interface to the hal runner helper daemon
 *
 * Copyright (C) 2006 Sjoerd Simons <sjoerd@luon.net>
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

#ifndef HALD_RUNNER_H
#define HALD_RUNNER_H

#include "device.h"

/* Successful run of the program */
#define HALD_RUN_SUCCESS 0x0
/* Process was killed because of running too long */
#define  HALD_RUN_TIMEOUT 0x1
/* Failed to start for some reason */
#define HALD_RUN_FAILED 0x2
/* Killed on purpose, e.g. hal_runner_kill_device */
#define HALD_RUN_KILLED 0x4

/* Default sane timeout */
#define HAL_HELPER_TIMEOUT 10000

typedef void (*HalRunTerminatedCB) (HalDevice *d, guint32 exit_type,
                                       gint return_code, gchar **error,
                                       gpointer data1, gpointer data2);

/* Start the runner daemon */
gboolean
hald_runner_start_runner(void);

/* Start a helper, returns true on a successfull start.
 * cb will be called on abnormal or premature termination
 * only
 */
gboolean
hald_runner_start (HalDevice *device, const gchar *command_line, char **extra_env,
		   HalRunTerminatedCB cb, gpointer data1, gpointer data2);

/* Run a helper program using the commandline, with input as infomation on
 * stdin */
void
hald_runner_run(HalDevice *device,
               const gchar *command_line, char **extra_env,
               guint32 timeout,
               HalRunTerminatedCB cb,
               gpointer data1, gpointer data2);
void
hald_runner_run_method(HalDevice *device,
		       const gchar *command_line, char **extra_env,
                       gchar *input, gboolean error_on_stderr,
                       guint32 timeout,
                       HalRunTerminatedCB  cb,
                       gpointer data1, gpointer data2);

void hald_runner_kill_device(HalDevice *device);
void hald_runner_kill_all();

/* called by the core to tell the runner a device was finalized */
void runner_device_finalized (HalDevice *device);

#endif
