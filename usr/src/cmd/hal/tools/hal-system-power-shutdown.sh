#!/bin/sh
# 
# hal-system-power-shutdown.sh
#
# Licensed under the Academic Free License version 2.1
#

. ./hal-functions
hal_check_priv hal-power-shutdown
hal_exec_backend
