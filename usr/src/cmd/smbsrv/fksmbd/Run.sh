#!/bin/sh

#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
#

# Helper program to run fksmbd (user-space smbd for debugging)
# using binaries from the proto area.

[ -n "$ROOT" ] || {
  echo "Need a bldenv to set ROOT=..."
  exit 1;
}

if [[ ! -w /var/smb || ! -w /var/run/smb ]]
then
  echo "Need to create/chown/chmod /var/smb /var/run/smb"
  echo "mkdir -p /var/run/smb"
  echo "chown -R $USER /var/smb /var/run/smb"
  echo "chmod -R a+rw  /var/smb /var/run/smb"
  exit 1;
fi

if [[ ! -r /var/smb/smbpasswd ]]
then
  echo "Need readable /var/smb/smbpasswd, i.e."
  echo 'chgrp staff /var/smb/smbpasswd'
  echo 'chmod 440   /var/smb/smbpasswd'
  exit 1;
fi

if [[ -e /var/smb/.pwd.lock && ! -w /var/smb/.pwd.lock ]]
then
  echo "Need to cleanup /var/smb/.pwd.lock, i.e."
  echo "rm -f /var/smb/.pwd.lock"
  exit 1;
fi

# OK, setup env. to run it.

export SMBD_DOOR_NAME="/tmp/fksmbd_door"
export SMB_SHARE_DNAME="/tmp/fksmbshare_door"

LD_LIBRARY_PATH=$ROOT/usr/lib/smbsrv:$ROOT/usr/lib:$ROOT/lib
export LD_LIBRARY_PATH

# normally runs with cwd=/ but this is more careful
cd /var/smb

# run with the passed options
exec $ROOT/usr/lib/smbsrv/fksmbd "$@"
