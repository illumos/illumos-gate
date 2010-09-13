#!/bin/sh
# 
# hal-system-power-reboot.sh
#
# Licensed under the Academic Free License version 2.1
#

. ./hal-functions
hal_check_priv hal-power-reboot
hal_exec_backend
