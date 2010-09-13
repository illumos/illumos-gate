#!/bin/sh
# 
# hal-system-power-hibernate.sh
#
# Licensed under the Academic Free License version 2.1
#

. ./hal-functions
hal_check_priv hal-power-hibernate
hal_exec_backend
