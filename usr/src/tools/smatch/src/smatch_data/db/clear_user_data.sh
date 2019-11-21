#!/bin/bash

echo "delete from caller_info where type = 8017; delete from return_states where type = 8017 or type = 9017;" | sqlite3 smatch_db.sqlite


