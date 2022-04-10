// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022, Michał Lach
 */
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/if.h>
#include <linux/cdev.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

#define SPOOFER_CDEV_LOCKED 1
#define SPOOFER_CDEV_NOT_LOCKED 0

#define SPOOFER_MINOR 0
#define SPOOFER_DEVICE_NAME "spoofer"

#define SPOOFER_ERRNO_NOERRORS 0x0
#define SPOOFER_ERRNO_NFREINIT 0x1

#define SPOOFER_ADDRESS_DEFAULT  0x00000000FFFFFFFFL
#define SPOOFER_NO_ADDRESS_MASK  BIT_MASK(63)
#define SPOOFER_TCP_ADDRESS_MASK BIT_MASK(62) 
#define SPOOFER_UDP_ADDRESS_MASK BIT_MASK(61) 

#define SPOOFER_PORT_DEFAULT    	0x0000FFFF
#define SPOOFER_NO_PORT_MASK    	BIT_MASK(31)
#define SPOOFER_EVERY_PORT_MASK 	BIT_MASK(30)
#define SPOOFER_TCP_PORT_MASK   	BIT_MASK(29)
#define SPOOFER_UDP_PORT_MASK   	BIT_MASK(28)

#define SPOOFER_NO_DEVICE       { 0 }

#define SPOOFER_IOCTL_BASE 0xF9
#define SPOOFER_IOCTL_SET_IP_SPOOF_ADDR  _IOW(SPOOFER_IOCTL_BASE, 1, long*)
#define SPOOFER_IOCTL_GET_IP_SPOOF_ADDR  _IOR(SPOOFER_IOCTL_BASE, 2, long*) 
#define SPOOFER_IOCTL_SET_PORT_TARGET    _IOW(SPOOFER_IOCTL_BASE, 3, int*)
#define SPOOFER_IOCTL_GET_PORT_TARGET    _IOR(SPOOFER_IOCTL_BASE, 4, int*) 
#define SPOOFER_IOCTL_SET_TCP_TARGET_DEV _IOW(SPOOFER_IOCTL_BASE, 5, char*)
#define SPOOFER_IOCTL_GET_TCP_TARGET_DEV _IOR(SPOOFER_IOCTL_BASE, 6, char*)
#define SPOOFER_IOCTL_SET_UDP_TARGET_DEV _IOW(SPOOFER_IOCTL_BASE, 7, char*)
#define SPOOFER_IOCTL_GET_UDP_TARGET_DEV _IOR(SPOOFER_IOCTL_BASE, 8, char*)

#define SPOOFER_SETTINGS_INIT() { \
	.ip       = (SPOOFER_ADDRESS_DEFAULT | SPOOFER_NO_ADDRESS_MASK), \
	.port     = (SPOOFER_PORT_DEFAULT    | SPOOFER_NO_PORT_MASK),    \
	.udp_dev  = SPOOFER_NO_DEVICE,       				 \
	.tcp_dev  = SPOOFER_NO_DEVICE,  				 \
}

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Michał Lach");
MODULE_DESCRIPTION("IPv4/MAC spoofer");
MODULE_VERSION("0.1");

struct filter_settings {
	unsigned long ip;
	unsigned int  port;
	char          udp_dev[IFNAMSIZ];
	char 	      tcp_dev[IFNAMSIZ];
};

static DEFINE_SPINLOCK(settings_lock);
static unsigned int netfilter_hook_handler(void *priv, struct sk_buff *skb,
		const struct nf_hook_state *state);
static int __init spoofer_init(void);
static void __exit spoofer_exit(void);
static int filter_comm_open(struct inode *node, struct file *filp);
static int filter_comm_close(struct inode *inode, struct file *filp);
static ssize_t filter_comm_read(struct file *filp, char __user *buf,
		size_t len, loff_t *off);
static ssize_t filter_comm_write(struct file *filp, const char __user *buf,
		size_t len, loff_t *off);
static long filter_comm_ioctl(struct file *filp, unsigned int cmd,
		unsigned long arg);
static int filter_proc_open(struct inode *node, struct file *filp);
static int filter_proc_close(struct inode *inode, struct file *filp);
static int filter_show(struct seq_file *file, void *v);
static void *filter_seq_start(struct seq_file *file, loff_t *pos);
static void *filter_seq_next(struct seq_file *file, void *v, loff_t *pos);
static void filter_seq_stop(struct seq_file *file, void *v);

static struct filter_settings settings = SPOOFER_SETTINGS_INIT();
static struct nf_hook_ops filter_ops = {
	.hook     = netfilter_hook_handler,
	.pf       = PF_INET,
	.priority = NF_IP_PRI_FIRST,
	.hooknum  = NF_INET_LOCAL_OUT,
	.priv     = &settings,
};
static dev_t major;
static struct cdev c_dev;
static struct class *dev_class;
static struct proc_dir_entry *filter_proc_entry;
static struct file_operations filter_comm_ops = {
	.owner          = THIS_MODULE,
	.open           = filter_comm_open,
	.release        = filter_comm_close,
	.read           = filter_comm_read,
	.write          = filter_comm_write,
	.unlocked_ioctl = filter_comm_ioctl,
};
static struct proc_ops filter_proc_ops = {
	.proc_open      = filter_proc_open,
	.proc_read_iter = seq_read_iter,
	.proc_lseek     = seq_lseek,
	.proc_release   = filter_proc_close,

};
static struct seq_operations filter_seqproc_ops = {
	.start = filter_seq_start,
	.stop  = filter_seq_stop,
	.next  = filter_seq_next,
	.show  = filter_show,
};
static atomic_t atomic_is_open = ATOMIC_INIT(SPOOFER_CDEV_NOT_LOCKED);
static atomic_t spoofer_errno = ATOMIC_INIT(SPOOFER_ERRNO_NOERRORS);

module_init(spoofer_init);
module_exit(spoofer_exit);
