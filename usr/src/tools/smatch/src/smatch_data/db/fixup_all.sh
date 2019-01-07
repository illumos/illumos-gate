#!/bin/bash

db_file=$1
cat << EOF | sqlite3 $db_file

delete from return_states where function = 'strlen';
delete from return_states where function = 'strnlen';
delete from return_states where function = 'sprintf';
delete from return_states where function = 'snprintf';

EOF

