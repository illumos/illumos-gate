#!/bin/bash

cat << EOF > trinity_smatch.h

#pragma once

/* Syscalls from arch/x86/syscalls/syscall_64.tbl */

#include "sanitise.h"
#include "syscall.h"
#include "syscalls/syscalls.h"

EOF

cat smatch_trinity_* >> trinity_smatch.c


for i in $(grep syscallentry smatch_trinity_*  | cut -d ' ' -f 3) ; do
    echo "extern struct syscallentry $i;" >> trinity_smatch.h
done

echo "" >> trinity_smatch.h
echo "struct syscalltable syscalls_smatch[] = {" >> trinity_smatch.h

for i in $(grep syscallentry smatch_trinity_*  | cut -d ' ' -f 3) ; do
    echo "{ .entry = &$i },"  >> trinity_smatch.h
done

echo "};" >> trinity_smatch.h
