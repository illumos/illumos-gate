#!/bin/sh
# 
# hal-system-lcd-set-brightness.sh
#
# Licensed under the Academic Free License version 2.1
#

. ./hal-functions
hal_check_priv hal-power-brightness
hal_exec_backend
