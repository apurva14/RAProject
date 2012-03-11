/*
 * wireless.h
 *
 *  Created on: Apr 13, 2010
 *      Author: ahmad
 */

#include <net/iw_handler.h>
#include <linux/wireless.h>	// includes the IOCTL call definitions
#include <linux/netdevice.h>

#include <linux/nsproxy.h>
#include <net/net_namespace.h>

#ifndef WIRELESS_H_
#define WIRELESS_H_

#define GET_POWER_INFO (SIOCGIWPOWER-SIOCSIWCOMMIT)
#define SET_POWER_INFO (SIOCSIWPOWER-SIOCSIWCOMMIT)

#define CAM	0
#define PSM 1

static char ifname[] = "wlan0";

/*
 * Emulating the wnic
 */
struct emulated_wnic {

	u_int8_t idle_state;

	unsigned long int initial_timestamp;
	/*
	 * A timestamp use to mark the time when the WNIC slept
	 * in jiffies
	 */
	unsigned long int sleep_timestamp;
	/*
	 * Time lapsed since the wnic went to sleep
	 * the first time (in jiffies)
	 */
	u_int32_t time_lapsed;

	/*
	 * Total idle time for connection_time_lapsed
	 * defined above (in millisecs)
	 */
	u_int32_t total_idle_time;


};

static struct emulated_wnic *wnic;

static struct net* get_net_current_process();
static int ec_wireless_print(struct net_device *, struct iwreq *,struct iw_request_info *);
static int ec_wireless_set_power_mode(struct net_device *, struct iwreq *,struct iw_request_info *, unsigned short);

static inline void wni_control(unsigned int signal); // stub, needs to be implemented
static inline int is_wnic_sleep(); // stub, needs to be implemented

/**
 * get_net_current_process()
 *
 * Get net (namespace) from
 * the current process running
 *
 */
static struct net* get_net_current_process() {
	struct task_struct *task;
	struct nsproxy *ns;
	struct net *net = NULL;

	rcu_read_lock();
	task = get_current();

	if (task != NULL) {
		ns = task_nsproxy(task);
		if (ns != NULL)
			net = get_net(ns->net_ns);
	}
	rcu_read_unlock();

	return net;
}


static int ec_wireless_print(struct net_device *dev, struct iwreq *wrq,
		struct iw_request_info *wrq_info) {

	wrq->u.power.flags = 0;

	dev->wireless_handlers->standard[GET_POWER_INFO](dev,/*&wrq_info*/NULL,
			&(wrq->u), NULL);

	int p_flags = (int) wrq->u.power.flags;
	int p_value = (int) wrq->u.power.value;
	int p_disabled = (int) wrq->u.power.disabled;

	printk(KERN_DEBUG "Power Flags : %d \n", p_flags);
	printk(KERN_DEBUG "Power Value: %d\n", p_value );
	printk(KERN_INFO "ec :: Power Mode: %s\n", p_disabled ? "CAM" : "PSM" );

	return 0;
}

static int ec_wireless_set_power_mode(struct net_device *dev,
		struct iwreq *wrq, struct iw_request_info *wrq_info,
		unsigned short power_mode) {

	printk (KERN_DEBUG "in .. : %d \n", power_mode);

	switch (power_mode) {

	case CAM:
		wrq->u.power.disabled = 1;
		break;

	case PSM:
		wrq->u.power.disabled = 0;
		break;

	default:
		return -1;
	}

	int ret = dev->wireless_handlers->standard[SET_POWER_INFO](dev,//&wrq_info
			NULL, &(wrq->u), NULL);

	if (ret >= 0) {
		int p_flags = (int) wrq->u.power.flags;
		int p_value = (int) wrq->u.power.value;
		int p_disabled = (int) wrq->u.power.disabled;

	printk(KERN_DEBUG "Power Flags : %d \n", p_flags);
	printk(KERN_DEBUG "Power Value: %d\n", p_value );
	printk(KERN_INFO "ec :: Power Mode: %s\n", p_disabled ? "CAM" : "PSM" );

	}

	return ret;
}

/*
 * Stub for handling the real wireless device.
 * Needs to be implemented for specific drivers
 */
static inline void wni_control(unsigned int signal){

	switch(signal){


	default:
		break;
	}
}
/*
 * Stub function for getting the state of real
 * WNI device
 */
static inline int is_wnic_sleep(){
	return 0;
}

#endif /* WIRELESS_H_ */
