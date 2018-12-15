#!/bin/bash

db_file=$1
cat << EOF | sqlite3 $db_file
/* we only care about the main ->read/write() functions. */
delete from caller_info where function = '(struct file_operations)->read' and file != 'fs/read_write.c';
delete from caller_info where function = '(struct file_operations)->write' and file != 'fs/read_write.c';
delete from caller_info where function = '(struct file_operations)->read' and caller != '__vfs_read';
delete from caller_info where function = '(struct file_operations)->write' and caller != '__vfs_write';
delete from function_ptr where function = '(struct file_operations)->read';
delete from function_ptr where function = '(struct file_operations)->write';
delete from caller_info where function = '__vfs_write' and caller != 'vfs_write';
delete from caller_info where function = '__vfs_read' and caller != 'vfs_read';
delete from caller_info where function = '(struct file_operations)->write' and caller = 'do_loop_readv_writev';
delete from caller_info where function = 'do_splice_from' and caller = 'direct_splice_actor';

/* delete these function pointers which cause false positives */
delete from caller_info where function = '(struct file_operations)->open' and type != 0;
delete from caller_info where function = '(struct notifier_block)->notifier_call' and type != 0;
delete from caller_info where function = '(struct mISDNchannel)->send' and type != 0;
delete from caller_info where function = '(struct irq_router)->get' and type != 0;
delete from caller_info where function = '(struct irq_router)->set' and type != 0;
delete from caller_info where function = '(struct net_device_ops)->ndo_change_mtu' and caller = 'i40e_dbg_netdev_ops_write';
delete from caller_info where function = '(struct timer_list)->function' and type != 0;

/* type 1003 is USER_DATA */
delete from caller_info where caller = 'hid_input_report' and type = 1003;
delete from caller_info where caller = 'nes_process_iwarp_aeqe' and type = 1003;
delete from caller_info where caller = 'oz_process_ep0_urb' and type = 1003;
delete from caller_info where function = 'dev_hard_start_xmit' and key = '\$' and type = 1003;
delete from caller_info where function like '%->ndo_start_xmit' and key = '\$' and type = 1003;
delete from caller_info where caller = 'packet_rcv_fanout' and function = '(struct packet_type)->func' and parameter = 1 and type = 1003;
delete from caller_info where caller = 'hptiop_probe' and type = 1003;
delete from caller_info where caller = 'p9_fd_poll' and function = '(struct file_operations)->poll' and type = 1003;
delete from caller_info where caller = 'proc_reg_poll' and function = 'proc_reg_poll ptr poll' and type = 1003;
delete from caller_info where function = 'blkdev_ioctl' and type = 1003 and parameter = 0 and key = '\$';
/* 9017 is USER_DATA3_SET */
delete from return_states where function='vscnprintf' and type = 9017;
delete from return_states where function='scnprintf' and type = 9017;
delete from return_states where function='vsnprintf' and type = 9017;
delete from return_states where function='snprintf' and type = 9017;
delete from return_states where function='sprintf' and type = 9017;
delete from return_states where function='vscnprintf' and type = 8017;
delete from return_states where function='scnprintf' and type = 8017;
delete from return_states where function='vsnprintf' and type = 8017;
delete from return_states where function='snprintf' and type = 8017;
delete from return_states where function='sprintf' and type = 8017;
/* There is something setting skb->sk->sk_mark and friends to user_data and */
/* because of recursion it gets passed to everything and is impossible to debug */
delete from caller_info where function = '__dev_queue_xmit' and type = 8017;
delete from caller_info where function = '__netdev_start_xmit' and type = 8017;
/* comparison doesn't deal with chunks, I guess.  */
delete from return_states where function='get_tty_driver' and type = 8017;
delete from caller_info where caller = 'snd_ctl_elem_write' and function = '(struct snd_kcontrol)->put' and type = 8017;
delete from caller_info where caller = 'snd_ctl_elem_read' and function = '(struct snd_kcontrol)->get' and type = 8017;
delete from caller_info where function = 'nf_tables_newexpr' and type = 8017 and key = '\$->family';
delete from caller_info where caller = 'fb_set_var' and function = '(struct fb_ops)->fb_set_par' and type = 8017 and parameter = 0;
delete from return_states where function = 'tty_lookup_driver' and parameter = 2 and type = 8017;

insert into caller_info values ('userspace', '', 'compat_sys_ioctl', 0, 0, 1003, 0, '\$', '1');
insert into caller_info values ('userspace', '', 'compat_sys_ioctl', 0, 0, 1003, 1, '\$', '1');
insert into caller_info values ('userspace', '', 'compat_sys_ioctl', 0, 0, 1003, 2, '\$', '1');

delete from caller_info where function = '(struct timer_list)->function' and parameter = 0;

/*
 * rw_verify_area is a very central function for the kernel.  The 1000000000
 * isn't accurate but I've picked it so that we can add "pos + count" without
 * wrapping on 32 bits.
 */
delete from return_states where function = 'rw_verify_area';
insert into return_states values ('faked', 'rw_verify_area', 0, 1, '0-1000000000[<=\$3]', 0, 0,   -1,      '', '');
insert into return_states values ('faked', 'rw_verify_area', 0, 1, '0-1000000000[<=\$3]', 0, 104,  2, '*\$', '0-1000000000');
insert into return_states values ('faked', 'rw_verify_area', 0, 1, '0-1000000000[<=\$3]', 0, 103, 3,  '\$', '0-1000000000');
insert into return_states values ('faked', 'rw_verify_area', 0, 2, '(-4095)-(-1)',     0, 0,   -1,      '', '');

delete from return_states where function = 'is_kernel_rodata';
insert into return_states values ('faked', 'is_kernel_rodata', 0, 1, '1', 0, 0,   -1,  '', '');
insert into return_states values ('faked', 'is_kernel_rodata', 0, 1, '1', 0, 103,  0,  '\$', '100000000-177777777');
insert into return_states values ('faked', 'is_kernel_rodata', 0, 2, '0', 0, 0,   -1,  '', '');

/*
 * I am a bad person for doing this to __kmalloc() which is a very deep function
 * and can easily be removed instead of to kmalloc().  But kmalloc() is an
 * inline function so it ends up being recorded thousands of times in the
 * database.  Doing this is easier.
 *
 */
delete from return_states where function = '__kmalloc';
insert into return_states values ('faked', '__kmalloc', 0, 1, '16', 0,    0,  -1, '', '');
insert into return_states values ('faked', '__kmalloc', 0, 1, '16', 0, 103,   0, '\$', '0');
insert into return_states values ('faked', '__kmalloc', 0, 2, '0,500000000-577777777', 0,    0, -1, '', '');
insert into return_states values ('faked', '__kmalloc', 0, 2, '0,500000000-577777777', 0, 103,  0, '\$', '1-4000000');
insert into return_states values ('faked', '__kmalloc', 0, 2, '0,500000000-577777777', 0, 1037,  -1, '', 400);
insert into return_states values ('faked', '__kmalloc', 0, 3, '0', 0,    0,  -1, '', '');
insert into return_states values ('faked', '__kmalloc', 0, 3, '0', 0,    103,  0, '\$', '4000000-long_max');

/*
 * Other kmalloc hacking.
 */
update return_states set return = '0,500000000-577777777' where function = 'kmalloc_slab' and return = 's64min-s64max';
update return_states set return = '0,500000000-577777777' where function = 'slab_alloc_node' and return = 's64min-s64max';
update return_states set return = '0,500000000-577777777' where function = 'kmalloc_large' and return != '0';
update return_states set return = '0,500000000-577777777' where function = 'kmalloc_order_trace' and return != '0';

delete from return_states where function = 'vmalloc';
insert into return_states values ('faked', 'vmalloc', 0, 1, '0,600000000-677777777', 0,    0, -1, '', '');
insert into return_states values ('faked', 'vmalloc', 0, 1, '0,600000000-677777777', 0, 103,  0, '\$', '1-128000000');
insert into return_states values ('faked', 'vmalloc', 0, 2, '0', 0,    0,  -1, '', '');

delete from return_states where function = 'ksize';
insert into return_states values ('faked', 'ksize', 0, 1, '0', 0,    0, -1, '', '');
insert into return_states values ('faked', 'ksize', 0, 1, '0', 0, 103,  0, '\$', '16');
insert into return_states values ('faked', 'ksize', 0, 2, '1-4000000', 0,    0,  -1, '', '');

/* store a bunch of capped functions */
update return_states set return = '0-u32max[<=\$2]' where function = 'copy_to_user';
update return_states set return = '0-u32max[<=\$2]' where function = '_copy_to_user';
update return_states set return = '0-u32max[<=\$2]' where function = '__copy_to_user';
update return_states set return = '0-u32max[<=\$2]' where function = 'copy_from_user';
update return_states set return = '0-u32max[<=\$2]' where function = '_copy_from_user';
update return_states set return = '0-u32max[<=\$2]' where function = '__copy_from_user';

update return_states set return = '0-8' where function = '__arch_hweight8';
update return_states set return = '0-16' where function = '__arch_hweight16';
update return_states set return = '0-32' where function = '__arch_hweight32';
update return_states set return = '0-64' where function = '__arch_hweight64';

/*
 * Preserve the value across byte swapping.  By the time we use it for math it
 * will be byte swapped back to CPU endian.
 */
update return_states set return = '0-u64max[==\$0]' where function = '__fswab64';
update return_states set return = '0-u32max[==\$0]' where function = '__fswab32';
update return_states set return = '0-u16max[==\$0]' where function = '__fswab16';
update return_states set return = '0-u64max[==\$0]' where function = '__builtin_bswap64';
update return_states set return = '0-u32max[==\$0]' where function = '__builtin_bswap32';
update return_states set return = '0-u16max[==\$0]' where function = '__builtin_bswap16';

delete from return_states where function = 'bitmap_allocate_region' and return = '1';
/* Just delete a lot of returns that everyone ignores */
delete from return_states where file = 'drivers/pci/access.c' and (return >= 129 and return <= 137);

update return_states set return = '(-4095)-s32max[<=\$1]' where function = 'get_user_pages' and return = 's32min-s32max';
update return_states set return = '(-4095)-s64max[<=\$1]' where function = 'get_user_pages' and return = 's64min-s64max';

/* Smatch can't parse wait_for_completion() */
update return_states set return = '(-108),(-22),0' where function = '__spi_sync' and return = '(-115),(-108),(-22)';

delete from caller_info where caller = '__kernel_write';

/* We sometimes use pre-allocated 4097 byte buffers for performance critical code but pretend it is always PAGE_SIZE */
update caller_info set value = 4096 where caller='kernfs_file_direct_read' and function='(struct kernfs_ops)->read' and type = 1002 and parameter = 1;
/* let's pretend firewire doesn't exist */
delete from caller_info where caller='init_fw_attribute_group' and function='(struct device_attribute)->show';
/* and let's fake the next dev_attr_show() call entirely */
delete from caller_info where caller='sysfs_kf_seq_show' and function='(struct sysfs_ops)->show';
insert into caller_info values ('fake', 'sysfs_kf_seq_show', '(struct sysfs_ops)->show', 0, 0, 1001, 0, '\$', '4096-2117777777777777777');
insert into caller_info values ('fake', 'sysfs_kf_seq_show', '(struct sysfs_ops)->show', 0, 0, 1002, 2, '\$', '4096');
insert into caller_info values ('fake', 'sysfs_kf_seq_show', '(struct sysfs_ops)->show', 0, 0, 1001, 2, '\$', '4096-2117777777777777777');
insert into caller_info values ('fake', 'sysfs_kf_seq_show', '(struct sysfs_ops)->show', 0, 0, 0,   -1, ''  , '');
/* config fs confuses smatch a little */
update caller_info set value = 4096 where caller='fill_read_buffer' and function='(struct configfs_item_operations)->show_attribute' and type = 1002 and parameter = 2;

/* smatch sees the memset() but not the subsequent changes */
update return_states set value = "" where function = 'gfs2_ea_find' and return = '0' and type = 101 and parameter = 3;

delete from type_value where type = '(struct fd)->file';
delete from type_value where type = '(struct fd)->flags';

/* This is sometimes an enum or a u64 */
delete from type_value where type = '(struct mc_cmd_header)->status';

/* this is handled in check_kernel.c */
delete from return_states where function = "__write_once_size";

update return_states set value = "s32min-s32max[\$1]" where function = 'atomic_set' and parameter = 0 and type = 1025;

/* handled in the check itself */
delete from return_states where function = 'atomic_inc_return' and (type = 8023 or type = 8024);
delete from return_states where function = 'atomic_add_return' and (type = 8023 or type = 8024);
delete from return_states where function = 'atomic_sub_return' and (type = 8023 or type = 8024);
delete from return_states where function = 'atomic_sub_and_test' and (type = 8023 or type = 8024);
delete from return_states where function = 'atomic_dec_and_test' and (type = 8023 or type = 8024);
delete from return_states where function = 'atomic_dec' and (type = 8023 or type = 8024);
delete from return_states where function = 'atomic_inc' and (type = 8023 or type = 8024);
delete from return_states where function = 'atomic_sub' and (type = 8023 or type = 8024);
delete from return_states where function = 'refcount_add_not_zero' and (type = 8023 or type = 8024);
delete from return_states where function = 'refcount_inc_not_zero' and (type = 8023 or type = 8024);
delete from return_states where function = 'refcount_sub_and_test' and (type = 8023 or type = 8024);

update return_states set return = '0-32,2147483648-2147483690' where function = '_parse_integer' and return = '0';
update return_states set value = '0-u64max' where function = '_parse_integer' and type = 1025 and parameter = 2 and key = '*$';

/* delete some function pointers which are sometimes byte units */
delete from caller_info where function = '(struct i2c_algorithm)->master_xfer' and type = 1027;

/* this if from READ_ONCE().  We can't know anything about the data.  */
delete from type_info where key = '(union anonymous)->__val';

EOF

# fixme: this is totally broken
call_id=$(echo "select distinct call_id from caller_info where function = '__kernel_write';" | sqlite3 $db_file)
for id in $call_id ; do
    echo "insert into caller_info values ('fake', '', '__kernel_write', $id, 0, 1003, 1, '*\$', '');" | sqlite3 $db_file
done

for i in $(echo "select distinct return from return_states where function = 'clear_user';" | sqlite3 $db_file ) ; do
    echo "update return_states set return = \"$i[<=\$1]\" where return = \"$i\" and function = 'clear_user';" | sqlite3 $db_file
done

echo "select distinct file, function from function_ptr where ptr='(struct rtl_hal_ops)->set_hw_reg';" \
        | sqlite3 $db_file | sed -e 's/|/ /' | while read file function ; do

    drv=$(echo $file | perl -ne 's/.*\/rtlwifi\/(.*?)\/sw.c/$1/; print')
    if [ $drv = "" ] ; then
        continue
    fi

    echo "update caller_info
          set function = '$drv (struct rtl_hal_ops)->set_hw_reg'
          where function = '(struct rtl_hal_ops)->set_hw_reg' and file like 'drivers/net/wireless/rtlwifi/$drv/%';" \
         | sqlite3 $db_file

    echo "insert into function_ptr values ('$file', '$function', '$drv (struct rtl_hal_ops)->set_hw_reg', 1);" \
         | sqlite3 $db_file
done

