#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/spinlock_types.h>
#include <linux/spinlock.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/vmalloc.h>

#include <linux/err.h>		//IS_ERR(), PTR_ERR()  
#include <linux/kthread.h>	//kthread_create(), kthread_run()  
#include <linux/sched.h>	//wake_up_process() 

#include <linux/delay.h>


#include "mtrace.h"


#define NETLINK_MYTRACE 28	//My Netlink sock number
#define MAX_MSGSIZE 4096 
#define MY_RB_SIZE 512 

#define MTRACE_DEBUG_ON

static DEFINE_SPINLOCK(mtrace_lck);
//global var
struct mtrace m1 = {
    .has_inited 	= MTRACE_UNINITED,
	.state 			= MTRACE_STAT_STOP,
    .nl_mtrace_fd 	= NULL,
    .task_rm 		= NULL
};


/*
 * mtrace_interface
 * @bio-the bio that is finished.
 */
void mtrace_bio_collect(struct bio *bio)
{
	bio_mt_t meta;
	if(bio->bytes_n && MTRACE_STARTED(&m1)){
#ifdef MTRACE_DEBUG_ON
		printk(KERN_INFO "[mtrace] - collected.\n");
#endif
    	mtrace_get_bio_meta(bio, &meta);
    	//will calc md5 next
    	//mtrace_bio_remain(bio, &meta);
	}
}



/*
 *	when recieving "stop" command from user-space, stop the tracing job and inform the user-space program.
 */
static void mtrace_stop(struct mtrace *_m)
{
	if(MTRACE_STARTED(_m)){
		MTRACE_SET_STOPED(_m);
		sendnlmsg(_m->nl_mtrace_fd, "exit", _m->uid);
	}
}

/*
 *  start tracing job - plant the probe
 */
static void mtrace_start(struct mtrace *_m, __u32 _uid)
{
	if(MTRACE_STOPED(_m)){
		MTRACE_SET_STARTED(_m); 
		_m->uid = _uid;
		_m->start_time = current_kernel_time();
		printk(KERN_INFO "[mtrace] - mtrace start - %ld.%ld ...\n", 
	   		_m->start_time.tv_sec, 
	        _m->start_time.tv_nsec);
	}
}


/*
 *  would be called when receiving a msg
 *  @__skb - the &struct sk_buff of recieving msg
 */
void kernel_receive(struct sk_buff *__skb)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh = NULL;
    char buf[10];
	struct mtrace *_m = &m1;
	
    skb = skb_get(__skb);
    nlh = (struct nlmsghdr *)skb->data;

    sprintf(buf,"%s",(char*)NLMSG_DATA(nlh));
    kfree_skb(skb);
#ifdef MTRACE_DEBUG_ON
	printk(KERN_INFO "[mtrace] - recv %s.\n", buf);
#endif
    if(0 == strcmp(buf, "start") && MTRACE_STOPED(_m)){
        spin_lock(&mtrace_lck);
		mtrace_start(_m,  nlh->nlmsg_pid);
        spin_unlock(&mtrace_lck);

		printk(KERN_INFO "[mtrace] - going to start trace - %d.\n", _m->state);
		wake_up_process(_m->task_rm);
    }

    if(0 == strcmp(buf, "stop") && MTRACE_STARTED(_m)){
        spin_lock(&mtrace_lck);
        mtrace_stop(_m);
        spin_unlock(&mtrace_lck);
        printk(KERN_INFO "[mtrace] - going to stop trace - %d.\n", _m->state);
    }
}

void _mtrace_sock_release(struct mtrace *_m)
{
    if(_m->nl_mtrace_fd){
        sock_release(_m->nl_mtrace_fd->sk_socket);
    }
}


static int __init mtrace_init2(void)  
{  
	struct mtrace *_m = &m1;
	int Err;
	
	//setup the netlink socket to transportation.
    struct netlink_kernel_cfg  cfg1 = {
            .groups=0,
            .input=kernel_receive,
            //.cb_mutex=NULL,
            };
	
	MTRACE_CLEAR_ERR(Err);
    _m->nl_mtrace_fd = netlink_kernel_create(&init_net, NETLINK_MYTRACE, &cfg1);
    if(!MTRACE_SOCK_INITED(_m)){
		MTRACE_SET_ERR_BIT(Err, E_SOCK_INIT);
        printk(KERN_ERR "[mtrace] - create a netlink socket error.\n");
		goto CLEAN_NONE;
    }else{
        printk(KERN_INFO "[mtrace] - create netlink socket success.\n");
    }


	//if sock init good & kthread init good, SET INITED & go.
	MTRACE_SET_INITED(_m);
	printk(KERN_INFO "[mtrace] - init2.\n");
	goto CLEAN_NONE;
	
CLEAN_SOCK:
	_mtrace_sock_release(_m);

CLEAN_NONE:
	return Err;
}  
  
static void __exit mtrace_exit2(void)
{
	//have not impl yet!
	struct mtrace *_m = &m1;
	MTRACE_UNSET_INITED(_m);
	
	printk(KERN_INFO "[mtrace] - goodbye2.\n");
}  


MODULE_LICENSE("GPL");  
module_init(mtrace_init2); 
module_exit(mtrace_exit2);  
