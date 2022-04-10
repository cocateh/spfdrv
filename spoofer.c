// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022, Michał Lach
 * TODO: implement userspace client
 */
#include "spoofer.h"

/* TODO: implement net_device specific filtering
int reregister_nf_hook(struct net *net, const struct nf_hook_ops *ops)
{
	int err = 0;
	nf_unregister_net_hook(&init_net, &filter_ops);
	err = nf_register_net_hook(&init_net, &filter_ops);
	return err;
}
*/

static int filter_show(struct seq_file *file, void *v)
{
	unsigned int port = ((struct filter_settings*)v)->port;
	// TODO: fix endianess related display issues (JUST USE ntohl()!!!)
	unsigned long ip  = ((struct filter_settings*)v)->ip;
	char *tcp_dev     = ((struct filter_settings*)v)->tcp_dev;
	char *udp_dev     = ((struct filter_settings*)v)->udp_dev;
	// TODO: fix bitmasks
	if (ip & SPOOFER_NO_ADDRESS_MASK)
	{
		seq_puts(file, "ip\t: off\n");
	} 
	else if (ip & SPOOFER_TCP_PORT_MASK)
	{
		seq_printf(file, "ip\t: %ld.%ld.%ld.%ld (tcp)\n",
				(ip >> 24) & 0xFF,
				(ip >> 16) & 0xFF,
				(ip >>  8) & 0xFF,
				(ip        & 0xFF));
	}
	else if (ip & SPOOFER_UDP_PORT_MASK)
	{
		seq_printf(file, "ip\t: %ld.%ld.%ld.%ld (udp)\n",
				(ip >> 24) & 0xFF,
				(ip >> 16) & 0xFF,
				(ip >>  8) & 0xFF,
				(ip        & 0xFF));
	}
	else
	{
		seq_printf(file, "ip\t: %ld.%ld.%ld.%ld (tcp/udp)\n",
				(ip >> 24) & 0xFF,
				(ip >> 16) & 0xFF,
				(ip >>  8) & 0xFF,
				(ip        & 0xFF));
	}

	if (port & SPOOFER_NO_PORT_MASK) {
		seq_puts(file, "port\t: off\n");
	} else if (port & SPOOFER_EVERY_PORT_MASK) {
		seq_puts(file, "port\t: every\n");
	} else if (port & (SPOOFER_TCP_PORT_MASK | SPOOFER_UDP_PORT_MASK)) {
		seq_printf(file, "port\t: %d (tcp/udp)\n",
				(unsigned short)port);
	} else if (port & SPOOFER_TCP_PORT_MASK) {
		seq_printf(file, "port\t: %d (tcp)\n",
				(unsigned short)port);
	} else if (port & SPOOFER_UDP_PORT_MASK) {
		seq_printf(file, "port\t: %d (udp)\n",
				(unsigned short)port);
	}

	if (strlen(tcp_dev)) {
		seq_printf(file, "tcp_dev\t: %s\n", tcp_dev);
	} else {
		seq_puts(file, "tcp_dev\t: (NO_DEVICE)\n");
	}

	if (strlen(udp_dev)) {
		seq_printf(file, "udp_dev\t: %s\n", udp_dev);
	} else {
		seq_puts(file, "udp_dev\t: (NO_DEVICE)\n");
	}

	return 0;
}

static void *filter_seq_start(struct seq_file *file, loff_t *pos)
{
	if (*pos > 0)
		return NULL;
	return &settings;
}

static void *filter_seq_next(struct seq_file *file, void *v, loff_t *pos)
{
	(*pos)++;
	return filter_seq_start(file, pos);
}

static void filter_seq_stop(struct seq_file *file, void *v)
{
	return;
}

static int filter_proc_close(struct inode *inode, struct file *filp)
{
	atomic_set(&atomic_is_open, SPOOFER_CDEV_NOT_LOCKED);
	return seq_release(inode, filp);
}

static int filter_proc_open(struct inode *node, struct file *filp)
{
	if (atomic_cmpxchg(&atomic_is_open, SPOOFER_CDEV_NOT_LOCKED,
				SPOOFER_CDEV_LOCKED))
	{
		return -EBUSY;
	}
	return seq_open(filp, &filter_seqproc_ops);
}

static int filter_comm_open(struct inode *node, struct file *filp)
{
	if (atomic_cmpxchg(&atomic_is_open, SPOOFER_CDEV_NOT_LOCKED,
				SPOOFER_CDEV_LOCKED))
	{
		return -EBUSY;
	}
	
	return 0;
}

static int filter_comm_close(struct inode *inode, struct file *filp)
{
	atomic_set(&atomic_is_open, SPOOFER_CDEV_NOT_LOCKED);
	return 0;
}

static ssize_t filter_comm_read(struct file *filp, char __user *buf,
		size_t len, loff_t *off)
{
	return -EINVAL;
}

static ssize_t filter_comm_write(struct file *filp, const char __user *buf,
		size_t len, loff_t *off)
{
	return -EINVAL;
}

static long filter_comm_ioctl(struct file *filp, unsigned int cmd,
		unsigned long arg)
{
	unsigned long flags;
	unsigned long bread = 0;
	int err = 0;
	spin_lock_irqsave(&settings_lock, flags);
	switch (cmd) {
	case SPOOFER_IOCTL_SET_IP_SPOOF_ADDR:
		bread = copy_from_user((unsigned long*)&(settings.ip),
				(unsigned long*)arg,
				sizeof(unsigned long));
		if (bread)
			goto copy_fail;
		break;
	case SPOOFER_IOCTL_GET_IP_SPOOF_ADDR:
		bread = copy_to_user((unsigned long*)arg,
				(unsigned long*)&(settings.ip),
				sizeof(unsigned long));
		if (bread)
			goto copy_fail;
		break;
	case SPOOFER_IOCTL_SET_PORT_TARGET:
		bread = copy_from_user((unsigned int*)&(settings.port),
				(unsigned int*)arg,
				sizeof(unsigned int));
		if (bread)
			goto copy_fail;
		break;
	case SPOOFER_IOCTL_GET_PORT_TARGET:
		bread = copy_to_user((unsigned int*)arg,
				(unsigned int*)&(settings.port),
				sizeof(unsigned int));
		if (bread)
			goto copy_fail;
		break;
	case SPOOFER_IOCTL_SET_TCP_TARGET_DEV:
		bread = copy_from_user((char*)&(settings.tcp_dev),
				(char*)arg,
				IFNAMSIZ);
		if (bread)
			goto copy_fail;
		break;
	case SPOOFER_IOCTL_GET_TCP_TARGET_DEV:
		bread = copy_to_user((char*)arg,
				(char*)&(settings.tcp_dev),
				IFNAMSIZ);
		if (bread)
			goto copy_fail;
		break;
	case SPOOFER_IOCTL_SET_UDP_TARGET_DEV:
		bread = copy_from_user((char*)&(settings.udp_dev),
				(char*)arg,
				IFNAMSIZ);
		if (bread)
			goto copy_fail;
		break;
	case SPOOFER_IOCTL_GET_UDP_TARGET_DEV:
		bread = copy_to_user((char*)arg,
				(char*)&(settings.udp_dev),
				IFNAMSIZ);
		if (bread)
			goto copy_fail;
		break;
	default:
		break;
	}
	
	spin_unlock_irqrestore(&settings_lock, flags);
	return 0;

copy_fail:
	spin_unlock_irqrestore(&settings_lock, flags);
	return -EFAULT;
}

static unsigned int netfilter_hook_handler(void *priv, struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned long flags;
	struct iphdr *iph;
	struct udphdr *udph;
	struct tcphdr *tcph;
	if (!skb)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	spin_lock_irqsave(&settings_lock, flags);

	// TODO: make filter address the settings
	if (iph->protocol == IPPROTO_UDP) {
		udph = udp_hdr(skb);
		// if (settings.ip & SPOOFER_NO_ADDRESS_MASK)
		// 	goto no_filtering;
		// else if (!(settings.ip & SPOOFER_UDP_ADDRESS_MASK))
		// 	goto no_filtering;

		iph->saddr = (int)settings.ip;
	} else if (iph->protocol == IPPROTO_TCP) {
		// TODO: implement tcp filtering
		tcph = tcp_hdr(skb);
	}
	iph->check = ip_fast_csum(iph, iph->tot_len >> 1);

no_filtering:
	spin_unlock_irqrestore(&settings_lock, flags);
	return NF_ACCEPT;
}

static int __init spoofer_init(void)
{
	int err;
	struct device *dev_ret;

	if ((err = alloc_chrdev_region(&major, SPOOFER_MINOR, 1,
				SPOOFER_DEVICE_NAME)))
	{
		return err;
	}
	if (IS_ERR(dev_class = class_create(THIS_MODULE,
					SPOOFER_DEVICE_NAME)))
	{
		unregister_chrdev_region(major, 1);
		return PTR_ERR(dev_class);
	}
	if (IS_ERR(dev_ret = device_create(dev_class, NULL, major, NULL,
					SPOOFER_DEVICE_NAME)))
	{
		class_destroy(dev_class);
		unregister_chrdev_region(major, 1);
		return PTR_ERR(dev_ret);
	}
	cdev_init(&c_dev, &filter_comm_ops);
	if ((err = cdev_add(&c_dev, major, 1))) {
		device_destroy(dev_class, major);
		class_destroy(dev_class);
		unregister_chrdev_region(major, 1);
		return err;
	}
	if ((err = nf_register_net_hook(&init_net, &filter_ops))) {
		cdev_del(&c_dev);
		device_destroy(dev_class, major);
		class_destroy(dev_class);
		unregister_chrdev_region(major, 1);
		return err;
	}
	if (IS_ERR(filter_proc_entry = proc_create(SPOOFER_DEVICE_NAME, 0444,
					NULL, &filter_proc_ops)))
	{
		proc_remove(filter_proc_entry);
		cdev_del(&c_dev);
		device_destroy(dev_class, major);
		class_destroy(dev_class);
		unregister_chrdev_region(major, 1);
		nf_unregister_net_hook(&init_net, &filter_ops);
		return PTR_ERR(filter_proc_entry);
	}

	return 0;
}

static void __exit spoofer_exit(void)
{
	proc_remove(filter_proc_entry);
	device_destroy(dev_class, major);
	class_destroy(dev_class);
	cdev_del(&c_dev);
	unregister_chrdev_region(major, 1);
	nf_unregister_net_hook(&init_net, &filter_ops);
	return;
}
