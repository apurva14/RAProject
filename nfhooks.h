/*
 * nfhooks.h
 *
 *  Created on: Apr 15, 2010
 *      Author: Ahmad Nazir Raja
 */

#ifndef NFHOOKS_H_
#define NFHOOKS_H_

/**
 * Netfilter includes
 */

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/tcp.h>
//#include "connections.h"
#include "wireless.h" 					// is_wnic_sleep();


#define BURST_SIZE_RATIO 3
#define NETWORK_DELAY_FACTOR 4

static struct nf_hook_ops post_nfho, pre_nfho;

/**
 * open_ack boolean value
 *
 * Open Ack:	ACK with congestion window set to the default value
 * Closed Ack:	ACK with zero sized congestion window
 */
static bool open_ack_flag = true;

static inline void recalculate_window_size(struct constate * connection);
static inline void reduce_window_size(struct constate * connection);
static inline void set_tcp_window_size(struct sk_buff* my_skb,struct tcphdr* tcph, struct iphdr* iph, u_int32_t window_size, u_int16_t window_scale);
//static inline void send_Duplicate_ACK(struct sk_buff *skb, u32 seq, u32 ack,
//				    u32 win, u32 ts, int oif,
//				    int reply_flags);
static inline int send_Duplicate_ACK(struct constate *connection);

/**
 * NETFILTER HOOKS
 */

static unsigned int hook_local_out(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out, int(*okfn)(
				struct sk_buff *)) {

	struct tcphdr* tcph;
	struct iphdr* iph;
	struct sk_buff* my_skb;



	u_int16_t state;
	u_int32_t connection_id;

//	u_int16_t iph_len;
//	u_int16_t skb_len;
//	u_int16_t tcplen;

	my_skb = skb;

	if (!my_skb)
		return NF_ACCEPT;

	iph = ip_hdr(my_skb);
	if (!iph)
		return NF_ACCEPT;
	if (iph->protocol != 6)
		return NF_ACCEPT; // if not TCP packet

//	iph_len = ip_hdrlen(my_skb);
	tcph = tcp_hdr(my_skb);

	/*
	 * Connection id is source port.. for outgoing traffic
	 */
	connection_id = ntohs(tcph->source);

	/*
	 * Get Connection from connection_id
	 */
	struct constate *connection = get_connection(&all_connections_head,
			connection_id);

	if ((connection == NULL)) {

		state = NO_CONNECTION;

		if (tcph->syn) {
			add_connection(&all_connections_head, iph, tcph, connection_id,
					state | SYNED);


		} else if (tcph->fin) { // for debugging
			//printk("ConId : %u No_CONNECTION\n", connection_id);
			add_connection(&all_connections_head, iph, tcph, connection_id,
					state | CLOSED);

		} else { // for debugging
			add_connection(&all_connections_head, iph, tcph, connection_id,
					state | UNKNOWN);

		}

	} else {

		update_rtt(connection, my_skb);//update_tcpi_rtt->node->rtt = temp_tcp_info.tcpi_rtt;
										//node->tcpi_rcv_rtt = temp_tcp_info.tcpi_rcv_rtt;
										//node->rtt_var = temp_tcp_info.tcpi_rttvar;

		state = connection->state;

		if ((state == SYNED) && tcph->syn && tcph->ack) {
			/*
			 * Shouldn't happen as client never takes the
			 * role of a server.. adding just in case
			 *
			 * This will fail since the connection id is
			 * always source port for outgoing packets.
			 */

			connection->state = state | ACKED;

		} else if ((state == (SYNED | ACKED)) && tcph->ack) {


			connection->state = state | ESTABLISHED;

			update_window_scale_value(connection,my_skb); //node->window_scale = temp_tcp_info.tcpi_rcv_wscale;
			update_tcpi_rcv_mss(connection,my_skb);

			connection->connection_start_time = jiffies;
			printk ("DEBUG:%d ConId: %u Local_Out EST con_start_time=jiffy \n", jiffies, connection->connection_id);
			mod_timer(&connection->timer, jiffies
					+ msecs_to_jiffies(playout_buffer_wait));
			printk ("DEBUG:%d ConId: %u Local_Out EST Calling TimeFn after 5000msec i.e. %d in jiffies \n", jiffies, connection->connection_id, msecs_to_jiffies(playout_buffer_wait));

		} else if ((state >= ESTABLISHED) && (state <= CLOSED) && tcph->fin) {
			//printk("ConId : %u EST FIN PCKT\n", connection_id);
			connection->state = state | CLOSED;

		} else if ((state == (SYNED | ACKED | ESTABLISHED | THROTTLE_DETECTION)) && tcph->ack) {



			switch (connection->choke_state){
			case PRE_CHOKE:

				/*
				 * Send a Zero Sized Window (Zero Ack)
				 * if the choke_state is 'Pre Choke' and
				 * update the it to 'Post Choke'
				 */
				connection->td_start_time = jiffies;
				printk ("DEBUG:%d ConId: %u Local_Out PreChoke Sending Choke Packet \n", jiffies, connection->connection_id);
				set_tcp_window_size(my_skb,tcph,iph, 0x00,0);
				//printk("ConId : %u LOCAL_OUT TD PRECHOKE\n", connection_id);
				connection->choke_state = POST_CHOKE;
				printk ("DEBUG:%d ConId: %u Local_Out window = %d \n", jiffies, connection->connection_id, tcph->window);


				break;

			/*
			 * todo:
			 * even though the choke_state is changed to
			 * post_choke, what is the guarantee that
			 * a packet will come to execute the following
			 * functionality
			 */
			case POST_CHOKE:
				/*
				 * Delay the first ACK for (2*RTT) msecs
				 * and update the choke state to 'Open ACK'
				 * to avoid multiple delays
				 */
//				connection->burst_time = connection->rcv_rtt * BANDWIDTH_RATIO;
				connection->burst_time = ((connection->rtt + connection->rtt_var) * CHOKE_FACTOR)/1000;
				//connection->burst_time = ((connection->rtt + connection->rtt_var) * )/1000;
				unsigned int wait_time = connection->td_start_time + msecs_to_jiffies(connection->burst_time);
				printk ("DEBUG:%d ConId: %u rtt = %d Local_Out PostChoke burst_time = %d wait_time= %u\n", jiffies, connection->connection_id, connection->rtt, connection->burst_time, wait_time );
				uint32_t temp_index = 0;
				uint8_t flag_break = 0;
				/*
				 * BAD BAD BAD code !!!
				 *
				 * Tried using msleep, schedule_timeout with
				 * TASK_INTERRUPTIBLE and TASK_UNINTERRUPTIBLE
				 * but the kernel gets stuck... probably a deadlock
				 *
				 * My assumption is that problem occurs during
				 * heavy traffic, when the local_out hook goes
				 * to sleep and there are incoming packets for
				 * the local_in hook...
				 *
				 * todo: set the task priority to the
				 * lowest value.. so that minimum time
				 * is wasted, but then it can delay in
				 * waking up
				 */
				//printk("ConId : %u LOCAL_OUT TD Waiting in Post Choke\n", connection_id);
				unsigned int temp;
				temp = jiffies;
				while (temp < wait_time){
					//printk("Waiting \n");
//					if (connection->flag == 2) {
//						printk ("DEBUG:%d ConId: %u 2 packets in local out\n", jiffies, connection->connection_id);
//						flag_break = 1;
//						break;
//					}
					for (temp_index=0; temp_index<10; temp_index++){

						// some operation
					}
					temp = jiffies;
				}
//				if (flag_break == 1) {
//					printk ("DEBUG:%d ConId: %u Sending one packet\n", jiffies, connection->connection_id);
//					set_tcp_window_size(my_skb,tcph,iph, 0x00,0);
//					connection->flag = 1;
//					flag_break = 0;
//					break;
//				}

				printk ("DEBUG:%d ConId: %u Local_Out PostChoke Still waiting; Now calling TimerFn after BurstTime i.e. %d in jiffies\n", jiffies, connection->connection_id, msecs_to_jiffies(
						connection->burst_time) );

//				u_int32_t atomic_wait = 0;
//				while (connection->burst_time > atomic_wait){
//					msleep_interruptible(20);
//					printk(KERN_DEBUG "-");
//					atomic_wait += 20;
//				}

//				msleep(connection->burst_time);

				/*
				 * Wait for 2*RTT time to stop calculating the new
				 * flow rate.
				 */
				//printk("ConId : %u LOCAL_OUT TD After Wait in Post Choke\n", connection_id);
				mod_timer(&connection->timer, jiffies + msecs_to_jiffies(
						connection->burst_time));
				printk ("DEBUG:%d ConId: %u Local_Out Post choke window Before= %d \n", jiffies, connection->connection_id, tcph->window);

//				connection->psmt_window_size_min = calculate_window_size(connection->flow_rate_normal, connection->rtt/1000);
//				connection->psmt_window_size = connection->psmt_window_size_min;
//				set_tcp_window_size(my_skb, tcph, iph, connection->psmt_window_size, connection->window_scale);
				printk ("DEBUG:%d ConId: %u Value of wait time %d \n", jiffies, connection->connection_id, jiffies + msecs_to_jiffies(
						connection->burst_time) );
				printk ("DEBUG:%d ConId: %u Local_Out Post choke window After = %d \n", jiffies, connection->connection_id, tcph->window);
				connection->choke_state = OPEN_ACK;

				break;

			/**
			 * No difference between OPEN_ACK and NO_OP in
			 * terms of functionality. Both send the outgoing
			 * packets unchanged.
			 *
			 * We have made two different states only for the
			 * LOCAL_IN HOOK i.e.
			 * if the state is OPEN_ACK, the new flow rate
			 * will be calculated names as flow_rate_td
			 *
			 * when the state is NO_OP, no calculation of
			 * flow rate
			 *
			 */
			case OPEN_ACK:
			case NO_OP:
			default:

				/*
				 * Send the packets without any modification
				 */
				printk ("DEBUG:%d ConId: %u Local_Out OPEN_ACk NO_OP \n", jiffies, connection->connection_id );
				break;
			}



		} else if (state == (SYNED | ACKED | ESTABLISHED | THROTTLE_DETECTION | PSMT)) {


			switch(connection->psmt_state){

			/*
			 * PSM Throttling starts with choking the connection
			 * so that a specific window size can be sent (Open ACK)
			 *
			 */
			//printk("ConId : %u EST FIN PCKT\n", connection_id);
			case INITIAL_CHOKE:
				printk ("DEBUG:%d ConId : %u Local Out: Initial Choke \n", jiffies, connection_id);
				set_tcp_window_size(my_skb,tcph,iph, 0x00,0);
				connection->count--;
				//printk ("DEBUG:%d ConId : %u Local Out: Initial Choke - Choke Sent\n", jiffies, connection_id);
				/*
				 * Wait for 2*RTT (or the same amount of time waited
				 * for during Throttling detection) before an Open ACK
				 * can be sent
				 *
				 * todo:
				 * This way of changing the state can cause the connection to
				 * get stuck since after the specified time period, if no ACK
				 * arrives naturally to the local_out hook, then no Window Size
				 * will be advertised. Hence, the better way is to wait in a
				 * similar manner as in Throttling Detection State i.e. get an
				 * ACK and wait for the specified time period before sending it.
				 *
				 * Currently we are just relying on the out going ACKs to the
				 * previously arrived incoming packets or acknowledgments to the
				 * keep alive packets.
				 *
				 */
//				connection->burst_time = ((connection->rtt + connection->rtt_var) * 1)/1000;
				connection->burst_time = ((connection->rtt) * 1)/1000;

				mod_timer(&connection->timer, jiffies + msecs_to_jiffies(
						connection->burst_time));
				printk ("DEBUG:%d ConId : %u Local Out: Initial Choke - Time Started Burst time = %d\n", jiffies, connection_id, connection->burst_time);
				printk("INITIAL CHOKE < ip_id: %d, Initial Wait : %d > \n",ntohs(iph->id), connection->burst_time);
				connection->psmt_state = INITIAL_WAIT;
				//printk ("DEBUG:%d ConId: %u Local Out: Initial Choke Exiting \n", jiffies, connection_id);
				break;

			case INITIAL_WAIT:
				//printk ("DEBUG:%d conid: %u Local Out: Initial Wait \n", jiffies, connection_id);
				//printk ("DEBUG:%d conid: %u Local Out: count = %d Before While Loop \n", jiffies, connection_id, connection->count);

				connection->dup_my_skb = skb_copy(my_skb, GFP_KERNEL); // other option - GFP_ATOMIC

				//memcpy(connection->dup_iph,iph, sizeof(iphdr);
				//memcpy(connection->dup_tcph, tcph, sizeof(tcphdr));

//				connection->dup_my_skb = my_skb;




//				connection->dup_iph = iph;
//				connection->dup_my_skb = my_skb;
//				connection->dup_tcph = tcph;

//				while (connection->count < 2) {
//					//Keep waiting for another packet to arrive
//					printk ("DEBUG:%d conid: %u Local Out: count = %d waiting for packet to arrive \n", jiffies, connection_id, connection->count);
//					//break;
//					if (connection->psmt_state == ADVERTISE_WINDOW_SIZE) {
//						if (connection->count > 1) {
//							set_tcp_window_size(my_skb,tcph,iph, 0,0); //choke ACK
//							printk ("DEBUG:%d conid: %u Local Out: count = %d Sending choke packet, still one packet in buffer \n", jiffies, connection_id, connection->count);
//							connection->count--;
//						}
//						break;
//					}
//				}
//				printk ("DEBUG:%d conid: %u Local Out: count = %d After While Loop \n", jiffies, connection_id, connection->count);
//				if (connection->count > 1) {
//					set_tcp_window_size(my_skb,tcph,iph, 0,0); //choke ACK
//					printk ("DEBUG:%d conid: %u Local Out: count = %d Sending choke packet, still one packet in buffer \n", jiffies, connection_id, connection->count);
//					connection->count--;
//					break;
//				}

				set_tcp_window_size(my_skb,tcph,iph, 0x00,0);
//				connection->count--;
				printk ("DEBUG:%d conid: %u Local Out: Initial Wait count = %d Sending choke packet\n", jiffies, connection_id, connection->count);
				//printk("INITIAL WAIT < ip_id: %d> \n",ntohs(iph->id));
				break;

			case ADVERTISE_WINDOW_SIZE:
				
//				win_size = WINDOW_SIZE(connection->data_arrived_td, connection->burst_time, connection->tcpi_rtt/1000);
				//connection->flag_s = 1;
				//printk ("DEBUG:%d ConId: %u Local_Out AWS window before = %d \n", jiffies, connection->connection_id, tcph->window);
				//set_tcp_window_size(my_skb, tcph, iph,connection->psmt_window_size, connection->window_scale);
				set_tcp_window_size(my_skb,tcph,iph, 0,0); //choke ACK
				printk ("DEBUG:%d ConId: %u Local_Out AWS window After = %d \n", jiffies, connection->connection_id, tcph->window);
				//printk ("DEBUG:%d conid: %u LocalOut AWS PSMT WS ACK Sent\n", jiffies, connection_id);
				connection->psmt_state = RECEIVE_PACKETS;


				/*
				 * This timer is to refresh the previous value set by the choke state,
				 * but what should its value be? lets keep a big value..
				 * timer wait: multiplying rtt by 100
				 */
				//mod_timer(&connection->timer, jiffies + msecs_to_jiffies(connection->rtt*100));
				/*
				 * Account for the transition time also before waking up
				 */
				//printk ("DEBUG:%d con_id: %u LocalOut AWSBefore Modify Sleep Timer \n", jiffies, connection_id );
				//modify_sleep_timer(connection,(connection->rtt * 2 -((connection->rtt_var*AGGRESSION_VALUE_N)/AGGRESSION_VALUE_D) - TRANSITION_TIME_SLEEP_TO_WAKE) / 1000);

				//printk ("DEBUG:%d conid: %u LocalOut AWSAfter Modify Sleep Timer \n", jiffies, connection_id);

//				if (EMULATE_WNIC){
//					scheduler(connection, EMULATE_SINGLE_PACKET, "emulate single packet sending");
//				}
				//printk ("DEBUG:%d ConId: %u LocalOut AWS Before calling scheduler \n", jiffies, connection_id);
				//scheduler(connection, NOT_IDLE, "Wake up - sending out a packet ..");
				//printk ("DEBUG:%d ConId:%u LocalOut AWS After calling scheduler \n", jiffies, connection_id);
				if (connection->chokeTimerInitiated_flag == 0) {
					mod_timer(&connection->timer, jiffies + msecs_to_jiffies(connection->rtt/1000));
					printk ("DEBUG:%d ConId: %u LocalOut AWS Setting Timer \n", jiffies, connection_id);
				}

				mod_timer(&connection->wake_timer, jiffies + BUFFER_TIME_FOR_EXTRA_PACKETS + msecs_to_jiffies(TRANSITION_TIME_SLEEP_TO_WAKE + SEND_SINGLE_PACKET_TIME));
				//printk ("DEBUG:%d ConId: %u LocalOut AWS After calling wake timer \n", jiffies, connection_id);

//
//				printk(
//				 		"ADVERTISE WINDOW < ip_id : %d, scale: %d, data_arrived_td: %d, burst_time: %d, rtt: %d, window_size : %d Bytes, Scaled : %x, Wake up after: %d msecs>\n",
//						ntohs(iph->id), connection->window_scale,
//						connection->data_iarrived_td, connection->burst_time,
//						connection->rtt/1000, connection->psmt_window_size,
//						connection->psmt_window_size >> connection->window_scale,
//						(connection->rtt-((connection->rtt_var*AGGRESSION_VALUE_N)/AGGRESSION_VALUE_D) - TRANSITION_TIME_SLEEP_TO_WAKE) / 1000);

				break;


			case CHOKE:
				/*
				 * The following condition occurs when specific sized window
				 * has been advertised but no data comes in (maybe because of
				 * pseudo streaming).
				 *
				 * In such a case, we'll have to send the window advertisement
				 * again and keep the wifi device awake to receive the tcp
				 * keep alive packets.
				 */
				//printk ("DEBUG:%d conid: %u LocalOut Choke \n", jiffies, connection_id);
//				if (connection->data_arrived_burst < DEFAULT_MSS_VALUE/2){
				if (connection->data_arrived_burst == 0){
					printk ("DEBUG:%d conid: %u LocalOut Choke Readvertise \n", jiffies, connection_id);
					set_tcp_window_size(my_skb, tcph, iph,
							connection->psmt_window_size, connection->window_scale);

					printk(
							"CHOKE :: Waiting for next burst < ip_id : %d, scale: %d, data_arrived_td: %d, burst_time: %d, rtt: %d, window_size : %d Bytes, Scaled : %x >\n",
							ntohs(iph->id), connection->window_scale,
							connection->data_arrived_td, connection->burst_time,
							connection->rtt/1000, connection->psmt_window_size,
							connection->psmt_window_size >> connection->window_scale);

				} else {
					printk ("DEBUG:%d Conid: %u LocalOut Choke Choke Ack \n", jiffies, connection_id);
					//recalculate_window_size(connection);
					//set_tcp_window_size(my_skb, tcph, iph,connection->psmt_window_size, connection->window_scale);
					connection->dup_my_skb1 = skb_copy(my_skb, GFP_KERNEL); // other option - GFP_ATOMIC

					//memcpy(connection->dup_iph1, iph, sizeof(struct iphdr);
					//memcpy(connection->dup_tcph1, tcph, sizeof(struct tcphdr));

					set_tcp_window_size(my_skb,tcph,iph, 0,0); //choke ACK
					connection->psmt_state = RECEIVE_PACKETS;

					/*
					 * Since we have started receiving the packets (as
					 * data_arrived_burst is greater than 0), we need to
					 * go back to the ADVERTISE_WINDOW state after 1 RTT.
					 * The reason is that we are not waiting for all
					 * the packets to arrive. Secondly, a data burst should
					 * be complete in one RTT, after that no data will arrive
					 * anyway, because we have just advertised a ZERO window
					 * (which takes 1/2 RTT to reach the server.)
					 *
					 * Precaution: Adding a cushion value of NETWORK_DELAY_FACTOR
					 * RTT in case of network problems
					 */
					printk ("DEBUG:%d con_id : %u LocalOut Choke Start timer\n", jiffies, connection_id);
//					mod_timer(&connection->timer, jiffies + msecs_to_jiffies(
//												(connection->rtt*NETWORK_DELAY_FACTOR)/1000));
					mod_timer(&connection->timer, jiffies + msecs_to_jiffies(connection->rtt/1000));
					//connection->chokeTimerInitiated_flag = 1;
//					printk( " ------------ ACTIVATED --------------\n-- Execute in %d msecs --\n", connection->tcpi_rtt/1000);


				}

				break;

			case RECEIVE_PACKETS:
				printk ("DEBUG:%d ConId: %u LocalOut Receive Packet \n", jiffies, connection_id);
				//recalculate_window_size(connection);
				//set_tcp_window_size(my_skb, tcph, iph,connection->psmt_window_size, connection->window_scale);
				connection->dup_my_skb1 = skb_copy(my_skb, GFP_KERNEL); // other option - GFP_ATOMIC
				set_tcp_window_size(my_skb,tcph,iph, 0,0); //choke ACKs


			default:
				break;
			}

		}

	}

	return NF_ACCEPT;

}

static unsigned int hook_local_in(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out, int(*okfn)(
				struct sk_buff *)) {

	struct tcphdr* tcph;
	struct iphdr* iph;
	struct sk_buff* my_skb;

	u_int16_t state;
	u_int32_t connection_id;
//	u_int8_t tcp_flag_syn;
//	u_int8_t tcp_flag_ack;
//	u_int8_t tcp_doff;

	unsigned int skb_len = 0;
	unsigned int iph_len = 0;
	unsigned int tcph_len = 20;		// TCP header
	unsigned int tcp_opt_len = 0;	// TCP options
	unsigned int tcp_payload = 0;
	unsigned int segment_size = 0;	// TCP Options + TCP payload,
									// corresponds to the MSS value
									// set during TCP Handshake

	my_skb = skb;

	if (!my_skb)
		return NF_ACCEPT;
	skb_len = my_skb->len;


	iph = ip_hdr(my_skb);
	if (!iph)
		return NF_ACCEPT;


	if (iph->protocol != 6)
		return NF_ACCEPT; // if not TCP packet


	iph_len = ip_hdrlen(my_skb);

	/**
	 * Even though the following statement should
	 * return the tcp header but it only works in case
	 * of outgoing packets.
	 *
	 * tcph = tcp_hdr(my_skb);
	 *
	 * Therefore we come up with our own way of casting.
	 *
	 * This problem only occurs from the incoming tcp
	 * packets.. maybe the headers are not initialized
	 * or what?
	 */

	//temporary modification for testing
	tcph = (struct tcphdr *) (my_skb->data + iph->ihl * 4);
	//struct tcphdr *tcph2 = (struct tcphdr *) skb_transport_header(my_skb);

	/*
	 * We have noticed that for wired ethernet connections,
	 * getting the tcph in the above manner works, but in
	 * case of wireless networks, tcph incorrectly points
	 * to the tcp flags like syn, ack, doff etc
	 *
	 * todo: In order to cater for that, we need to get these
	 * values manually.
	 */

	tcp_opt_len = (tcph->doff * 4) - (sizeof(struct tcphdr));


	/**
	 * Calculating TCP Payload
	 */
	tcp_payload = skb_len - tcph_len - tcp_opt_len - iph_len;
	segment_size = tcp_payload + tcp_opt_len;


	/*
	 * Connection id is destination port.. for incoming traffic
	 */
	connection_id = ntohs(tcph->dest);

//	printk(" << \n");
//	printk(" 0 - ip_id         : %d \n", ntohs(iph->id));
//	printk(" 1 - connection_id : %d \n", connection_id);

	/*
	 * Fetch Connection from the connection_id
	 */
	struct constate *connection = get_connection(&all_connections_head,
			connection_id);
//	printk(" 3 - id received   : %d\n", connection ? connection->connection_id: -1);
//	printk(" 4 - state         : %d\n", connection ? connection->state : -1);
//	printk(" 5 - syn           : %d\n", ntohs(tcph->syn));
//	printk(" 6 - ack           : %d\n", ntohs(tcph->ack));
//	printk(" 7 - tcp->dest     : %d\n", ntohs(tcph->dest));
//	printk(" 8 - tcp->doff     : %d\n", tcph->doff);
//	printk(" 9 - tcp           : %x - %x - %x - %x - %x - %x - %x - %x - %x - %x - %x - %x \n"
//																, *(tcph),*(tcph+1),*(tcph+2)
//																,*(tcph+3), *(tcph+4),*(tcph+5)
//																,*(tcph+6), *(tcph+7),*(tcph+8)
//																,*(tcph+9), *(tcph+10),*(tcph+11));
//	printk(" 10 - tcp2           : %x - %x - %x - %x - %x - %x - %x - %x - %x - %x - %x - %x \n"
//																	, *(tcph2),*(tcph2+1),*(tcph2+2)
//																	,*(tcph2+3), *(tcph2+4),*(tcph2+5)
//																	,*(tcph2+6), *(tcph2+7),*(tcph2+8)
//																	,*(tcph2+9), *(tcph2+10),*(tcph2+11));

//	printk(" 11- direct        : %x - %x - %x - %x - %x - %x - %x \n"
//											, (long)*(my_skb->data + iph->ihl * 4)
//											, (long)*(my_skb->data + iph->ihl * 4 + 4)
//											, (long)*(my_skb->data + iph->ihl * 4 + 8)
//											, (long)*(my_skb->data + iph->ihl * 4 + 12)
//											, (long)*(my_skb->data + iph->ihl * 4 + 16)
//											, (long)*(my_skb->data + iph->ihl * 4 + 20)
//											, (long)*(my_skb->data + iph->ihl * 4 + 24));
//	printk(" >> \n");


	if ((connection == NULL)) {

		state = NO_CONNECTION;

		if (tcph->syn) {
			/*
			 * Shouldn't happen as client never takes the
			 * role of a server.. adding just in case
			 *
			 * This will fail since the connection id is
			 * always destination port for incoming packets.
			 */
			add_connection(&all_connections_head, iph, tcph, connection_id,	state | SYNED);

		} else if (tcph->fin) { // for debugging
			//printk("ConId : %u No_CONNECTION\n", connection_id);
			add_connection(&all_connections_head, iph, tcph, connection_id,	state | CLOSED);

		} else { // for debugging
			add_connection(&all_connections_head, iph, tcph, connection_id,	state | UNKNOWN);
		}

	} else {

		refresh_rtt(connection, my_skb);
		update_tcpi_rtt(connection, my_skb);

		state = connection->state;



		if ((state == SYNED) && tcph->syn && tcph->ack) {
			connection->state = state | ACKED;

		} else if ((state == (SYNED | ACKED)) && tcph->ack) {
			/*
			 * Shouldn't happen since client never takes the
			 * roll of a server.. adding just in case
			 *
			 * This will fail since the connection id is
			 * always destination port for incoming packets.
			 */
			connection->state = state | ESTABLISHED;

			/*
			 * Only state is updated here... for debugging
			 * purposes..
			 */

		} else if ((state >= ESTABLISHED) && (state <= CLOSED) && tcph->fin) {
			//printk("ConId : %u EST FIN PCKT\n", connection_id);
			connection->state = state | CLOSED;

		} else if ((state == (SYNED | ACKED | ESTABLISHED)) && tcph->ack) {
			//printk ("DEBUG:%d ConId: %u Local_IN EST Adding packets to temp_data_arrived \n", jiffies, connection->connection_id );
			//printk ("DEBUG:%d ConId: %u Local_IN EST tcp_payload = %d \n", jiffies, connection->connection_id, tcp_payload );
			connection->total_packet_count++;
			connection->temp_data_arrived += tcp_payload;
			update_flow_rate_normal(connection);


		} else if ((state == (SYNED | ACKED | ESTABLISHED | THROTTLE_DETECTION))
				&& tcph->ack) {

			connection->total_packet_count++;

			switch(connection->choke_state){

			case PRE_CHOKE:
			case POST_CHOKE:

				/*
				 * Keep on operating in the same way as in
				 * 'Established' state
				 */
				if (connection->flag == 0) {
					connection->flag = 1;
					printk ("DEBUG:%d ConId: %u Local_IN flag 0 -> 1 \n", jiffies, connection->connection_id );
				}
				if (connection->flag == 1) {
					connection->flag = 2;
					printk ("DEBUG:%d ConId: %u Local_IN flag 1 -> 2 \n", jiffies, connection->connection_id );
				}
				printk ("DEBUG:%d ConId: %u Local_IN PreChoke PostChoke Still Adding packets to temp_data_arrived \n", jiffies, connection->connection_id );
				printk ("DEBUG:%d ConId: %u Local_IN PreChoke PostChoke tcp_payload = %d \n", jiffies, connection->connection_id, tcp_payload );
				connection->temp_data_arrived += tcp_payload;
				update_flow_rate_normal(connection);
				break;

			case OPEN_ACK:
				/*
				 * calculate new flow rate
				 */
				printk ("DEBUG:%d ConId: %u Local_IN OPEN_ACK Now adding packets to data arrived_td data_arrived_td = %d \n", jiffies, connection->connection_id, connection->data_arrived_td );

				printk ("DEBUG:%d ConId: %u Local_IN OPEN_ACK Now adding packets to data arrived_td tcp_payload = %d \n", jiffies, connection->connection_id, tcp_payload );
				connection->packet_count_td++;
				connection->data_arrived_td += tcp_payload;
				printk ("DEBUG:%d ConId: %u Local_IN OPEN_ACK Now adding packets to data arrived_td= %d \n", jiffies, connection->connection_id, connection->data_arrived_td );
				update_flow_rate_td(connection);

				connection->temp_data_arrived += tcp_payload;
				break;
			case NO_OP:
			default:
				/*
				 * Don't calculate the flow rates.
				 * Only update the total data
				 * arrived.
				 */
				connection->temp_data_arrived += tcp_payload;
				printk ("DEBUG:%d ConId: %u Local_IN NO_OP Default Still Adding packets to temp_data_arrived \n", jiffies, connection->connection_id );
				break;
			}


		} else if (state == (SYNED | ACKED | ESTABLISHED | THROTTLE_DETECTION | PSMT)) {

			connection->total_packet_count++;

			switch(connection->psmt_state){

			case INITIAL_CHOKE:
			case INITIAL_WAIT:
				connection->count++;
				printk ("DEBUG:%d ConId: %u LocalIn count = %d INIT CHOKE INIT WAIT \n", jiffies, connection_id, connection->count);
				break;
			case ADVERTISE_WINDOW_SIZE: // TODO: break; ? NO break .. otherwise, data_arrived_burst will not be updated
			case CHOKE:
			case RECEIVE_PACKETS:
				if (connection->flag_s == 0)
					break;
				printk ("DEBUG:%d ConId: %u LocalIn AWSCHKRP \n", jiffies, connection_id);
				connection->temp_data_arrived += tcp_payload;

				update_flow_rate_psmt(connection);
				connection->data_arrived_burst += tcp_payload;

				printk(
						"RECEIVE PACKETS <ip_id : %d, Segment_size : %d, tcpi_rcv_mss : %d, Payload : %d, Data Arrived Burst : %u, psmt_window_size : %u, diff : %u , psmt_state: %s (%d)> \n",
						ntohs(iph->id), segment_size, connection->tcpi_rcv_mss,
						tcp_payload, connection->data_arrived_burst,
						connection->psmt_window_size,
						(connection->psmt_window_size
								- connection->data_arrived_burst),
						get_psmt_state_name(connection->psmt_state), connection->psmt_state);
				printk("DEBUG: %d ConId: %u psmt_window_size: %u data_arrived_burst: %u tcpi_rcv_mss %d \n", jiffies, connection_id, connection->psmt_window_size, connection->data_arrived_burst ,connection->tcpi_rcv_mss);
				if ((( connection->psmt_window_size - connection->data_arrived_burst) < 50) ||  (connection->psmt_window_size < connection->data_arrived_burst)) {

					printk ("DEBUG:%d ConId: %u LocalIn If Condition \n", jiffies, connection_id);
					connection->flow_rate_inst = (connection->data_arrived_burst *1000)/(connection->rtt/1000);

					/*
					 * Recalculate the Window Size, if required (to achieve throughput)
					 */
					//recalculate_window_size(connection);
					//connection->psmt_state = ADVERTISE_WINDOW_SIZE;

					//connection->data_arrived_burst = 0;
					connection->recievedFullBurst_flag = 1;
					/*
					 * Set the wifi device to sleep mode
					 * (if in Awake Mode at the moment)
					 * and wake up in less than an RTT.
					 *
					 */
					//printk ("DEBUG:%d ConId: %u LocalIn Before calling schedular \n", jiffies, connection_id);
					//scheduler(connection, IDLE, "received full burst");
					//printk ("DEBUG:%d ConId: %u LocalIn After Calling schedular \n", jiffies, connection_id);
				}


			default:
				break;
			}

		}


	}

	return NF_ACCEPT;
}

static inline void recalculate_window_size(struct constate * connection){
	// TODO: PSMT_WIN_SIZE does not changes, actually when fr_psmt > fr_n, so in that case psmt_win_size should dec, which actually
	// does not occur in this case, as we do not recieve data according to win_size.

	if (connection == NULL) return;
	printk ("DEBUG:%d ConId: %u Start Recalculate_Win_Size psmt_win_size = %d \n", jiffies, connection->connection_id, connection->psmt_window_size);
	printk ("DEBUG:%d ConId: %u flow_rate_psmt = %d flow_rate_normal = %d min_psmt_thruput = %d \n", jiffies, connection->connection_id, connection->flow_rate_psmt, connection->flow_rate_normal, connection->min_psmt_throughput);
	if (connection->flow_rate_psmt	< (connection->flow_rate_normal*connection->min_psmt_throughput)/100) {
		connection->psmt_window_size += connection->tcpi_rcv_mss;

		printk(	" -- Inc WinSize <psmt_window_size : %u> \n",connection->psmt_window_size);

	} else if (connection->flow_rate_psmt >= (connection->flow_rate_normal*connection->max_psmt_throughput)/100) {
		printk(	" -- Red WinSize <psmt_window_size : %u> \n",connection->psmt_window_size);
		reduce_window_size(connection);
	}
	printk ("DEBUG:%d ConId: %u End Recalculate_Win_Size psmt_win_size = %d \n", jiffies, connection->connection_id, connection->psmt_window_size);
}

static inline void set_tcp_window_size(struct sk_buff* my_skb,
		struct tcphdr* tcph, struct iphdr* iph, u_int32_t window_size, u_int16_t window_scale) {

	u_int16_t tcplen;

	if (my_skb == NULL || tcph == NULL || iph == NULL || window_scale<0 || window_size < 0)
		return;

	tcplen = my_skb->len - ip_hdrlen(my_skb);

	/*
	 * Set Window Size after scaling
	 */
	tcph->window = htons(window_size>>window_scale);

	/*
	 * Check sum
	 */
	tcph->check = 0;
//	tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial(
//			(char *) tcph, tcplen, 0));
	tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial((char *) tcph, tcplen, 0));
}

static inline int send_Duplicate_ACK(struct constate *connection) {
		struct tcphdr* tcph;
		struct iphdr* iph;
		u_int32_t connection_id;

		if (connection->flag_dupack == 1) {
			//iph = ip_hdr(connection->dup_my_skb);
			//Have commented the below line, if this line is uncommented, system hangs
			//tcph = tcp_hdr(connection->dup_my_skb);
			// TODO: The tcph header is still not correctly captured
			//tcph = (struct tcphdr *) (connection->dup_my_skb->data + iph->ihl * 4);
			//connection_id = ntohs(tcph->dest);
			//set_tcp_window_size(connection->dup_my_skb, tcph, iph,connection->psmt_window_size, connection->window_scale);
			printk ("DEBUG:%d ConId: %u send_duplicate_ack win_size = %d \n", jiffies, connection->connection_id, connection->psmt_window_size);
			return dst_output(connection->dup_my_skb);
		}
		else {
			//iph = ip_hdr(connection->dup_my_skb1);
//			//Have commented the below line, if this line is uncommented, system hangs
//			//tcph = tcp_hdr(connection->dup_my_skb);
//			// TODO: The tcph header is still not correctly captured
//			tcph = (struct tcphdr *) (connection->dup_my_skb1->data + iph->ihl * 4);
//			connection_id = ntohs(tcph->dest);
//			set_tcp_window_size(connection->dup_my_skb1, tcph, iph,connection->psmt_window_size, connection->window_scale);
			printk ("DEBUG:%d ConId: %u send_duplicate1_ack win_size = %d \n", jiffies, connection->connection_id, connection->psmt_window_size);

			return dst_output(connection->dup_my_skb1);
		}
}

/**
 * Structures used for Hook Registration
 */

/**

 * hook_local_outget tcphdr

 * hook_local_out

 *
 * Deals with with outgoing traffic from local processes.
 */
static struct nf_hook_ops hook_local_out_ops __read_mostly =
{ .pf = PF_INET, .priority = 1, .hooknum = NF_INET_LOCAL_OUT,
		.hook = hook_local_out, };

/**
 * hook_local_in
 *
 * Deals with with incoming traffic for local processes.
 */
static struct nf_hook_ops hook_local_in_ops = //__read_mostly =
{ .pf = PF_INET, .priority = NF_IP_PRI_LAST, .hooknum = NF_INET_LOCAL_IN,
		.hook = hook_local_in, };

#endif /* NFHOOKS_H_ */
