#!/bin/bash

if echo $1 | grep -q '^-p' ; then
    PROJ=$(echo $1 | cut -d = -f 2)
    shift
fi

info_file=$1

if [[ "$info_file" = "" ]] ; then
    echo "Usage:  $0 -p=<project> <file with smatch messages>"
    exit 1
fi

bin_dir=$(dirname $0)
db_file=smatch_db.sqlite

files=$(grep "insert into caller_info" $info_file | cut -d : -f 1 | sort -u)
for c_file in $files; do
    echo "FILE $c_file"
    echo "delete from caller_info where file = '$c_file';" | sqlite3 $db_file
    echo "delete from return_states where file = '$c_file';" | sqlite3 $db_file
    echo "delete from call_implies where file = '$c_file';" | sqlite3 $db_file
    echo "delete from return_implies where file = '$c_file';" | sqlite3 $db_file
done

tmp_file=$(mktemp)

grep "insert into caller_info" $info_file > $tmp_file
${bin_dir}/fill_db_caller_info.pl "$PROJ" $tmp_file $db_file

grep "insert into return_states" $info_file > $tmp_file
${bin_dir}/fill_db_sql.pl "$PROJ" $tmp_file $db_file

grep "into call_implies" $info_file > $tmp_file
${bin_dir}/fill_db_sql.pl "$PROJ" $tmp_file $db_file

grep "into return_implies" $info_file > $tmp_file
${bin_dir}/fill_db_sql.pl "$PROJ" $tmp_file $db_file

rm $tmp_file

${bin_dir}/fixup_all.sh $db_file
if [ "$PROJ" != "" ] ; then
    ${bin_dir}/fixup_${PROJ}.sh $db_file
fi

