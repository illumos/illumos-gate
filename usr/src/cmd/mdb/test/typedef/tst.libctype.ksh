$MDB /lib/libc.so <<EOF
::typedef uint8_t rm_t
::typedef -l
::print -at rm_t
::sizeof rm_t
EOF
