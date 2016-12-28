#include <linux/module.h>	//
#include <linux/init.h>		//
#include <linux/kernel.h>

#include <linux/spinlock_types.h>
#include <linux/spinlock.h>


#include <linux/skbuff.h>	//struct sk_buff
#include <linux/netlink.h>	//nlmsg_new
#include <linux/vmalloc.h>	//vmalloc,vfree

#include <linux/crypto.h>			//
#include <linux/scatterlist.h>		//


#include "mtrace.h"


#define NETLINK_MYTRACE 28	//My Netlink sock number
#define MAX_MSGSIZE 4096 
#define MY_RB_SIZE 512 


typedef struct data{
    bio_mt_t mt;                //meta data
    unsigned char *bf_ptr;      //data
    
    //...other fields...

}dt_t;




#define MTRACE_DEBUG_ON

static DEFINE_SPINLOCK(mtrace_lck);
//static DEFINE_SPINLOCK(mtrace_thr_num_lck);
//global var
struct mtrace m1 = {
    .has_inited 	= MTRACE_UNINITED,
	.state 			= MTRACE_STAT_STOP,
	.threads_num	= 0,
    .nl_mtrace_fd 	= NULL,
    .task_rm 		= NULL,
    .bdev 			= "mmcblk0"
};

void mtrace_send_msg(struct mtrace *_m, unsigned char *_payload,unsigned int _payload_size)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nlh;
//	int payload_size = strlen(_payload) + 1;//for the \0
	int err = 0;
	
	skb_out = nlmsg_new(_payload_size , GFP_ATOMIC);
	if(!skb_out){
		printk(KERN_ERR "[mtrace mtrace_send_msg] - Failed to allocate new skb.\n");
   		goto OUT;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_NOOP, _payload_size,0);//netlink.h: #define NLMSG_NOOP		0x1	/* Nothing.		*/
	if(!nlh){
		printk(KERN_ERR "[mtrace mtrace_send_msg] - Failed to nlmsg_put payload into skb.\n");
   		goto OUT;
	}

	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	memcpy(nlmsg_data(nlh), _payload, _payload_size);
	
	err = nlmsg_unicast(_m->nl_mtrace_fd , skb_out, _m->uid);
	if(err){
    	printk(KERN_ERR "[mtrace mtrace_send_msg] - send failed\n");
	}
#ifdef MTRACE_DEBUG_ON
	else{
		printk(KERN_INFO "[mtrace] send ok\n");
	}
#endif
OUT:
	return ;		
}

struct payload{
	unsigned int plen;
	char cmd[10];
};

void mtrace_send_cmd(struct mtrace *_m, char *cmd)
{
	struct payload p;
	p.plen = sizeof(struct payload);
	strcpy(p.cmd, cmd);
	mtrace_send_msg(_m, (unsigned char*)&p, p.plen);
}



#define print_debug(_rb_entry) printk(KERN_INFO "[mtrace] - Get a bio done: %c,%12lu,%10d,%s\n", \
										(_rb_entry)->RW,			\
										(_rb_entry)->bi_sector,		\
										((_rb_entry)->bytes_n),		\
										(_rb_entry)->comm);


void mtrace_get_bio_meta(struct bio *bio, bio_mt_t *_rb_entry)
{
    //////time
    _rb_entry->delay = current_kernel_time();
   
    //////others
    _rb_entry->RW = bio->bi_rw & WRITE ? 'W' : 'R';
    _rb_entry->bi_sector = bio->bi_sector - ((bio->bytes_n) >> 9);
   	_rb_entry->bytes_n = bio->bytes_n;
    memcpy(_rb_entry->comm, bio->mt_comm, 18);
    bdevname(bio->bi_bdev, _rb_entry->b);
#ifdef MTRACE_DEBUG_ON
	print_debug(_rb_entry);
#endif
}



int mtrace_bio_calc_md5(struct bio *bio,unsigned char* md5)
{
	int segno;
    struct bio_vec *bvec;
	struct hash_desc desc;
	
	struct scatterlist sg;
	int err = 0;
	
	desc.flags = 0;
	desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if(IS_ERR(desc.tfm)){ goto OUT; }


	err = crypto_hash_init(&desc);
	if (err){ goto FREEHASH; }
	
	sg_init_table(&sg, 1);
 
    __bio_for_each_segment(bvec,bio,segno,0){
        sg_set_page(&sg, bvec->bv_page, bvec->bv_len, bvec->bv_offset);
        err = crypto_hash_update(&desc, &sg, sg.length);
		if (err){ goto FREEHASH; }
    }
	err = crypto_hash_final(&desc, md5);
FREEHASH:
	crypto_free_hash(desc.tfm);
OUT:
	return err;
}


#define mtrace_bio_is_target(_m, bio, b) (strcmp(bdevname(bio->bi_bdev, b), _m->bdev) == 0)


/*
 * mtrace_interface
 * @bio-the bio that is finished.
 */
void mtrace_bio_collect(struct bio *bio)
{
	int err;
	struct mtrace *_m = &m1;
	bio_mt_t entry_tmp;

	
	if(bio->bytes_n && MTRACE_STARTED(_m) /*&& mtrace_bio_is_target(_m, bio, b)*/){
		mtrace_get_bio_meta(bio, &entry_tmp);

		printk(KERN_INFO "[mtrace] - collected.\n");

		if(entry_tmp.bytes_n <= 4096) {
			err = mtrace_bio_calc_md5(bio, entry_tmp.md5);
			if(err){
				printk(KERN_INFO "[mtrace] - md5 calc error.\n");
			}else{
				printk(KERN_INFO "[mtrace] - md5 calc success.\n");
				entry_tmp.plen = sizeof(bio_mt_t);
				mtrace_send_msg(_m, (unsigned char*)&entry_tmp, entry_tmp.plen);
			//	mtrace_send_cmd(_m,"bio!");
			}
		}
	}
}



/*
 *	when recieving "stop" command from user-space, stop the tracing job and inform the user-space program.
 */
static void mtrace_stop(struct mtrace *_m)
{
	if(MTRACE_STARTED(_m)){
		MTRACE_SET_STOPED(_m);
	}
}

/*
 *  start tracing job - plant the probe
 */
static void mtrace_start(struct mtrace *_m, __u32 _uid)
{
	if(MTRACE_STOPED(_m)){		 
		_m->uid = _uid;
		_m->start_time = current_kernel_time();
		printk(KERN_INFO "[mtrace] - mtrace start - %ld.%ld ...\n", 
	   		_m->start_time.tv_sec, 
	        _m->start_time.tv_nsec);
		MTRACE_SET_STARTED(_m);
	}
}





/*
 *  would be called when receiving a msg
 *  @__skb - the &struct sk_buff of recieving msg
 */
void kernel_receive(struct sk_buff *__skb)
{
    struct nlmsghdr *nlh = NULL;
    char buf[10];
	struct mtrace *_m = &m1;
	
    nlh = (struct nlmsghdr *)__skb->data;
    sprintf(buf,"%s",(char*)nlmsg_data(nlh));
#ifdef MTRACE_DEBUG_ON
	printk(KERN_INFO "[mtrace] - recv %s.\n", buf);
#endif
    if(0 == strcmp(buf, "start") && MTRACE_STOPED(_m)){
        spin_lock(&mtrace_lck);
		mtrace_start(_m,  nlh->nlmsg_pid);
        spin_unlock(&mtrace_lck);
		printk(KERN_INFO "[mtrace] - going to start trace - %d.\n", _m->state);
    }

    if(0 == strcmp(buf, "stop") && MTRACE_STARTED(_m)){
        spin_lock(&mtrace_lck);
        mtrace_stop(_m);
        spin_unlock(&mtrace_lck);
		mtrace_send_cmd(_m, "exit");
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
            //.groups=0,
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
	printk(KERN_INFO "[mtrace] - init2 v3_for_md5_trans_test.\n");
	goto CLEAN_NONE;
	
//CLEAN_SOCK:
//	_mtrace_sock_release(_m);

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
