/*
 * ec.c
 *
 *  Created on: Mar 13, 2010
 *      Author: Ahmad Nazir Raja
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

/**
 * Kernel - User Communication Include Files
 */

#include <asm/siginfo.h>	//siginfo
#include <linux/rcupdate.h>	//rcu_read_lock
#include <linux/sched.h>	//find_task_by_pid_type << obsolete..
#include <linux/delay.h>	// void msleep(unsigned int sleep_time);
#include <linux/debugfs.h>
#include <linux/uaccess.h>

/**
 * Wireless Extensions
 */
#include <linux/netdevice.h>
#include <net/iw_handler.h>
#include <linux/netdevice.h>

/**
 * Local includes
 */
#include "wireless.h"
#include "ec.h"
#include "connections.h"
#include "nfhooks.h"

struct dentry *file;
struct task_struct *task;

static struct net *net;
static struct net_device *dev;
static struct iwreq wrq;
static struct iw_request_info wrq_info;

/*
 * Execution Number
 * Provided by the user at module installation
 */
static int num = 0;

/**
 * Counter keeps count of the number of signals sent to the user?
 */
static int counter = 0;

static ssize_t write_pid(struct file *file, const char __user *buf,
		size_t count, loff_t *ppos) {

	char mybuf[10];
	int pid = 0;
	int ret;
	struct siginfo info;
	struct task_struct *t = get_current();
	/* read the value from user space */
	if (count > 10)
		return -EINVAL;
	copy_from_user(mybuf, buf, count);
	sscanf(mybuf, "%d", &pid);
	printk("pid = %d\n", pid);

	/* send the signal */
	memset(&info, 0, sizeof(struct siginfo));
	info.si_signo = SIG_TEST;
	info.si_code = SI_QUEUE; // this is bit of a trickery: SI_QUEUE is normally used by sigqueue from user space,
	// and kernel space should use SI_KERNEL. But if SI_KERNEL is used the real_time data
	// is not delivered to the user space signal handler function.

	//info.si_int = counter++; //real time signals may have 32 bits of data.

	/**
	 * Flag for 'Choking and un-choking' mechanism
	 */
	//open_ack_flag = (1 + open_ack_flag)%2;

	int r = 0;
	/*
	 if (open_ack_flag) {
	 open_ack_flag = false;
	 r = ec_wireless_set_power_mode(dev, &wrq, &wrq_info,CAM);

	 } else {
	 open_ack_flag = true;
	 r = ec_wireless_set_power_mode(dev, &wrq, &wrq_info,PSM);
	 }

	 printk	(KERN_DEBUG "Set power mode executed : %d \n", r);
	 */
	info.si_int = open_ack_flag;

	//	ec_wireless_print(dev, &wrq, &wrq_info);

	//spin_lock(&my_spinlock);
	//display_connections_info(con_state);

	display_connections_info(&all_connections_head);

//	unsigned int sleep_time = 10000;
//	printk(KERN_DEBUG "About to sleep for %d secs", sleep_time/1000);
//	msleep(sleep_time);
//	printk(KERN_DEBUG "Woke up..");

	//spin_unlock(&my_spinlock);

	rcu_read_lock();

	/**
	 * Searching for the process in user-space
	 */
	for_each_process(task)
	{
		//printk("%s [%d]\n",task->comm , task->pid);
		if (task->pid == pid) {
			t = task;
		}
	}

	if (t == NULL) {
		printk("no such pid\n");
		rcu_read_unlock();
		return -ENODEV;
	}
	rcu_read_unlock();
	ret = send_sig_info(SIG_TEST, &info, t); //send the signal


	if (ret < 0) {
		printk("error sending signal\n");
		return ret;
	}
	return count;
}

static const struct file_operations my_fops = { .write = write_pid, };

/**
 * Initialize module
 *
 */
static int __init ec_module_init(void)
{
	test_identifier = jiffies;
	printk(KERN_INFO "\nec :: MODULE INITIALIZATION : id = %d\n", test_identifier );

	/**
	 * Initialize the settings to communicate with
	 * the wireless device
	 */
	net = get_net_current_process();
	dev = dev_get_by_name(net, "eth1");
	printk(KERN_INFO "net %s\n", net);
	if (dev == NULL) printk(KERN_ERR "ec :: Wireless device not detected .. \n");
	else printk(KERN_INFO "ec :: Wireless device detected : %s\n", dev);
	strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

	/**
	 * Connection Tracking
	 */

	all_connections_head=NULL;
	spin_lock_init( &all_connections_spinlock);


	/**
	 * DEBUGGING:
	 * For debugging purposes, user should be able to send
	 * the kernel signal so that it can call some function
	 *
	 * For this purpose, we need to know the pid of the
	 * user-space process. We use debugfs for this. As soon
	 * as a pid is written to this file, a signal is sent
	 * to that pid.
	 *
	 * Debugfs must be mounted before using
	 * this signaling mechanism.
	 *
	 * # mount -t debugfs debugfs /sys/kernel/debug/
	 *
	 * Only root can send the signal to the user-space
	 * process.
	 *
	 */
	printk("Before creating file \n");
	file = debugfs_create_file("signalconfpid", 0200, NULL, NULL, &my_fops);
	printk("After creating file \n");
	/**
	 * Hook Registeration
	 */
	 //nf_register_hook(&myhook_ops); // temporary hook
	 nf_register_hook(&hook_local_out_ops); // local out
	 nf_register_hook(&hook_local_in_ops); // local in


	 if (EMULATE_WNIC){
		 printk("In Emulate WNIC \n");
		 wnic = kmalloc(sizeof(struct emulated_wnic), GFP_KERNEL);
		 wnic->idle_state = NOT_IDLE;
		 wnic->initial_timestamp = 0;
		 wnic->sleep_timestamp = 0;
		 wnic->time_lapsed = 0;
		 wnic->total_idle_time = 0;
	 }

	printk(KERN_INFO "ec :: MODULE ENABLED\n" );

	return 0;

}

/**
 * Exit/Clean-up module
 *
 */
static int __exit ec_module_exit(void)
{

	nf_unregister_hook(&hook_local_out_ops);
	nf_unregister_hook(&hook_local_in_ops);

	display_connections_info(&all_connections_head);

	delete_all(&all_connections_head);

	debugfs_remove(file);
	printk(KERN_INFO "ec :: MODULE DISABLED : id = %d\n", test_identifier );

	return 0;
}

module_init(ec_module_init);
module_exit(ec_module_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ahmad Nazir Raja");

