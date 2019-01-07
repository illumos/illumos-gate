#!/bin/bash

db_file=$1


cat << EOF | sqlite3 $db_file
PRAGMA synchronous = OFF;
PRAGMA cache_size = 800000;
PRAGMA journal_mode = OFF;
PRAGMA count_changes = OFF;
PRAGMA temp_store = MEMORY;
PRAGMA locking = EXCLUSIVE;

CREATE INDEX type_size_idx on type_size (type);
CREATE INDEX type_val_idx on type_value (type);

EOF


