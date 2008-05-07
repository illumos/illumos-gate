#!/bin/sh
# 
# hal-system-power-suspend.sh
#
# Licensed under the Academic Free License version 2.1
#

. ./hal-functions
hal_check_priv hal-power-suspend
hal_exec_backend
