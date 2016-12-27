#include <linux/module.h>		//
#include <linux/init.h>			//
#include <linux/kernel.h>		//
#include <linux/crypto.h>		// md5_calc
#include <linux/scatterlist.h>	//
#include <linux/vmalloc.h>		// vmalloc vfree
								//kthread
#include <linux/err.h>		//IS_ERR(), PTR_ERR()  
#include <linux/kthread.h>	//kthread_create(), kthread_run()  
							
#include <linux/sched.h>	//wake_up_process() 
#include <linux/delay.h>	//wait_queue


#include <linux/skbuff.h>	//struct sk_buff
#include <linux/netlink.h>	//nlmsg_new
#include <linux/spinlock_types.h>
#include <linux/spinlock.h>

#include "mtrace.h"

#define MTRACE_DEBUG_ON
#define NETLINK_MYTRACE 28	//My Netlink sock number
#define MAX_MSGSIZE 4096 
#define MY_RB_SIZE 512 		//Warn: It must be a power of 2.
#define MY_RB_IN_INDEX(RBptr) ((RBptr)->in & (MY_RB_SIZE - 1))


//Ring Buffer Def
struct rb_data{
    bio_meta mt;                
    unsigned char *bf_ptr;      //data
    //...other fields...
};

struct simple_ring_buf{
    struct rb_data buf[MY_RB_SIZE];
	void (*srb_do_idx_before_pop)(struct simple_ring_buf *, int);
    int in;     //next idx to write in, need to be locked, here will be access by [bio_end_io] multi-producer
    int out;    //next idx to read out, ,here is only single-customer
};
void srb_mtrace_do_idx_before_pop(struct simple_ring_buf *_rbuf, int idx);

struct simple_ring_buf rb1 = {
	.srb_do_idx_before_pop = srb_mtrace_do_idx_before_pop;
    .in = 0,
    .out = 0,
};
static DEFINE_SPINLOCK(in_lck);
DECLARE_WAIT_QUEUE_HEAD(wq);

/*
 *  calc the 32-bit-hex md5 value
 *  @str - the pointer to the data that would be calc md5
 *  @len - length of the data that would be calc md5
 *  @output - where to store the md5-value
 */
static int calc_md5(unsigned char *str, unsigned int len, unsigned char *output)
{
    int err;
    struct scatterlist sg;
    struct crypto_hash *tfm;
    struct hash_desc desc;
    tfm = crypto_alloc_hash("md5", 0, CRYPTO_TFM_REQ_MAY_SLEEP);

    if(IS_ERR(tfm)){
        return -1;
    }

    desc.tfm = tfm;
    desc.flags = 0;
    sg_init_one(&sg, (unsigned char*)str, len);

    err = crypto_hash_init(&desc);
    if(err){
        goto ERR;
    }

    err = crypto_hash_update(&desc, &sg, len);
    if(err){
        goto ERR;
    }
    err = crypto_hash_final(&desc, output);
    if(err){
        goto ERR;
    }
ERR:
    crypto_free_hash(tfm);
    return err ? -1 : 0;  
}



/*
 *  calc the list of md5 values of data_ptr in chunking with BLK_SIZE.
 *  @size - size of the buf pointed by @data_ptr
 *  @data_ptr - the pointer to the data that is being calc md5 value.
 *  @return - the raw md5 value in unsigned char
 *  INFO:this function not used in this version. 
 *  next version will do these changes:
 *  send to user-space the raw md5 value & convert the format to HEX in user-space.
 */
#define MTRACE_BLK_SIZE 4096
int calc_md5_list_v2(int size, unsigned char *data_ptr, unsigned char *md5list)
{
    unsigned char md5temp[16];

    int size_left, size_togo, size_calc, j;
    /*
     *  md5list format - 
     *  <32-md5value>-<32-md5value>
     */

    size_left = size;
    size_calc =0;
    j = 0;
    while(size_left){
        if(size - size_calc > MTRACE_BLK_SIZE){
            size_togo = MTRACE_BLK_SIZE;
        }
        else{
            size_togo = size - size_calc;
        }
        if(calc_md5(data_ptr + size_calc, size_togo, md5temp)){
            return -1;
        }

        strncpy(md5list + j * 16, md5temp, 16);
        size_calc += size_togo;
        size_left -= size_togo;

        j++;
    }
    return 0;
}


void raw2md5str(int num_md5, unsigned char* raw, char* str)
{
    int i = 0, j = 0;
    while(num_md5){
        for(i = 0; i < 16; i++){
            sprintf((str + (i << 1) + (j * 33)), "%02x" ,*((__u8*)(raw + i)));
        }
        num_md5--;
        if(num_md5){
            sprintf((str + (i << 1) + j * 33), "-");
        }
        j++;
    }
}

void format2buf(char *buf, struct bio_meta *meta, char* _l)
{
    sprintf(buf, "%5ld.%-10ld,%c,%12lu,%10d,%15s,%s\n",
                    meta->delay.tv_sec,
                    meta->delay.tv_nsec,
                    meta->RW,
                    meta->bi_sector,
                    (meta->bytes_n),
                    meta->comm,
                    _l);
}
void format2bufLong(char *buf, struct bio_meta *meta, char* _l, int seq)
{
    sprintf(buf, "[L-%d]%5ld.%-10ld,%c,%12lu,%10d,%15s,%s\n", seq,
                    meta->delay.tv_sec,
                    meta->delay.tv_nsec,
                    meta->RW,
                    meta->bi_sector,
                    (meta->bytes_n),
                    meta->comm,
                    _l);
}




#define OUTPUTBUFSIZE       512
#define OUTPUTONETIMESIZE   270
#define OUTPUTONETIME       264


/*
 *  pop all bucket out of the ring buf
 *  only one kthread(task_rm) do this job. 
 */
int srb_pop_all(struct simple_ring_buf *_rbuf)
{
    int len = _rbuf->in - _rbuf->out;
    int idx;

    if(len <= 0){
        return -1;//rbuf empty
    }
    while(len){
        idx = _rbuf->out & (MY_RB_SIZE - 1);
        _rbuf->srb_do_idx_before_pop(_rbuf, idx);
        _rbuf->out += 1;
        len--;
    }
    return 0;
}

/*
 * push one entry into the buffer.
 * I do the shallow-copy.
 */
int srb_push_uninterruptable_shallow(struct simple_ring_buf *_rbuf,  struct rb_data *_rb_entry)
{
    if(MY_RB_SIZE - _rbuf->in + _rbuf->out <= 0){
#ifdef MTRACE_DEBUG_ON
		printk(KERN_INFO "[mtrace] - rbuf full!\n");
#endif
        return -1;//rbuf full
    }
    _rbuf->buf[MY_RB_IN_INDEX(_rbuf)].bf_ptr 			= _rb_entry->bf_ptr;			/*vmalloced ptr*/
    _rbuf->buf[MY_RB_IN_INDEX(_rbuf)].mt.delay.tv_sec 	= _rb_entry->mt.delay.tv_sec; 	/*other field*/
    _rbuf->buf[MY_RB_IN_INDEX(_rbuf)].mt.delay.tv_nsec 	= _rb_entry->mt.delay.tv_nsec;
    _rbuf->buf[MY_RB_IN_INDEX(_rbuf)].mt.RW 			= _rb_entry->mt.RW;
    _rbuf->buf[MY_RB_IN_INDEX(_rbuf)].mt.bi_sector 		= _rb_entry->mt.bi_sector;
    _rbuf->buf[MY_RB_IN_INDEX(_rbuf)].mt.bytes_n		= _rb_entry->mt.bytes_n;
    strncpy(_rbuf->buf[MY_RB_IN_INDEX(_rbuf)].mt.comm, _rb_entry->mt.comm, 15); 
	_rbuf->in += 1;
	return 0;
}

int srb_push_shallow(struct simple_ring_buf *_rbuf,  struct rb_data *_rb_entry)
{
	int err;
	spin_lock(&in_lck);
	err = srb_push_uninterruptable_shallow(_rbuf, _rb_entry);
	spin_unlock(&in_lck);
	return err;
}


/*
 * return if the rbuf is empty.
 */
bool srb_not_empty(struct simple_ring_buf *_rbuf)
{
    return _rbuf->in - _rbuf->out > 0;
}





static DEFINE_SPINLOCK(mtrace_lck);
//global var
struct mtrace m1 = {
    .has_inited 	= MTRACE_UNINITED,
	.state 			= MTRACE_STAT_STOP,
    .nl_mtrace_fd 	= NULL,					//
    .task_rm 		= NULL					//
};

void mtrace_form_trace_send(struct bio_meta *meta, int num_md5, unsigned char* md5);


//do something before pop
void srb_mtrace_do_idx_before_pop(struct simple_ring_buf *_rbuf, int idx)
{
	struct mtrace *_m = &m1;
	unsigned char *md5list = NULL;
	struct bio_meta * idx_bio_meta = &(_rbuf->buf[idx].mt);
	unsigned char * idx_bf_ptr = _rbuf->buf[idx].bf_ptr;
	unsigned int bytes = idx_bio_meta->bytes_n;
	unsigned int numd5 = bytes >> 12;
	
	if(idx_bf_ptr)
	{
		md5list = (unsigned char *)kmalloc((numd5 << 4), GFP_ATOMIC);
		if(!md5list){
			goto EKMALLOC_MD5_LIST;
		}

		err = calc_md5_list_v2(bytes, idx_bf_ptr, md5list);//md5-value
		if(err){
			goto ECALC_MD5_LIST;		
		}
		if(MTRACE_STARTED(_m)){
			mtrace_form_trace_send(idx_bio_meta, numd5, md5list);
		}
		kfree(md5list);
ECALC_MD5_LIST:
EKMALLOC_MD5_LIST:
		vfree(idx_bf_ptr);
	}
}


void mtrace_send_msg(struct mtrace *_m, const char * _payload)
{
	struct sk_buff *skb_out;
	struct nlmsghdr *nlh;
	int payload_size = strlen(_payload);
	int err = 0;
	
	skb_out = nlmsg_new(payload_size , GFP_ATOMIC);
	if(!skb_out){
		printk(KERN_ERR "[mtrace mtrace_send_msg] - Failed to allocate new skb.\n");
   		goto OUT;
	}

	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_NOOP, payload_size,0);//netlink.h: #define NLMSG_NOOP		0x1	/* Nothing.		*/
	if(!nlh){
		printk(KERN_ERR "[mtrace mtrace_send_msg] - Failed to nlmsg_put payload into skb.\n");
   		goto OUT;
	}

	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	strncpy(nlmsg_data(nlh), _payload, payload_size);
	
	err = nlmsg_unicast(_m->nl_mtrace_fd , skb_out, _m->uid);
	if(err){
    	printk(KERN_ERR "[mtrace mtrace_send_msg] - send failed - %s\n", _payload);
	}
#ifdef MTRACE_DEBUG_ON
	else{
		printk(KERN_INFO "[mtrace] send ok - %s\n", _payload);
	}
#endif
OUT:
	return ;		
}



//form trace and output
void mtrace_form_trace_send(struct bio_meta *meta, int num_md5, unsigned char* md5)
{
    //send to userspace
    char outputbuff[OUTPUTBUFSIZE];
	char temp[OUTPUTONETIMESIZE];
	int ik, k, len, i;
	struct mtrace *_m = &m1;
    char *md5str = (char *)kmalloc(((32 + 1) * num_md5) + 3, GFP_ATOMIC);
	
    if(!md5str){
        return;
    }
    raw2md5str(num_md5, md5, md5str);
#ifdef MTRACE_DEBUG_ON
    printk(KERN_INFO "[mtrace] - Trace: %5ld.%-10ld,%c,%12lu,%10d,%15s,%s\n", 
                                meta->delay.tv_sec,
                                meta->delay.tv_nsec,
                                meta->RW,
                                meta->bi_sector,
                                (meta->bytes_n),
                                meta->comm,
                                md5str);
#endif
#ifdef SPLIT_SEND_MSG
    if(num_md5 > 8){
        //large message 
        len = (32 + 1) * num_md5; 
        ik = 0; 
        i = 0;
        while(len > 0){
            k = len < OUTPUTONETIME ? len : OUTPUTONETIME;
            strncpy(temp ,md5str + ik, k);
            format2bufLong(outputbuff,  meta, temp, i);
            mtrace_send_msg(_m, outputbuff);
            i++; ik += k; len -= k;
        }
    }
	else
#endif
    {
        format2buf(outputbuff, meta, md5str);
        mtrace_send_msg(_m, outputbuff);
    }
	
//STOP:
    kfree(md5str);
}




void mtrace_get_bio_meta(struct bio *bio, struct bio_meta *ret)
{
    //////time
    ret->delay = current_kernel_time();
   
    //////others
    ret->RW = bio->bi_rw & WRITE ? 'W' : 'R';
    ret->bi_sector = bio->bi_sector - ((bio->bytes_n) >> 9);
    ret->bytes_n = bio->bytes_n;
    strncpy(ret->comm, bio->mt_comm, 15);
    
#ifdef MTRACE_DEBUG_ON
    //printk(KERN_INFO "[mtrace] - Get a bio done: %5ld.%-10ld,%c,%12lu,%10d,%15s\n", 
    printk(KERN_INFO "[mtrace] - Get a bio done: %5ld.%-10ld,%c,%12lu,%10d,%15s\n", 
                                    ret->delay.tv_sec,
                                    ret->delay.tv_nsec,
                                    ret->RW,
                                    ret->bi_sector,
                                    (ret->bytes_n),
                                    ret->comm);
#endif
}



int mtrace_bio_remain(struct bio *bio, struct rb_data *_rb_entry)
{
    int calc_size = 0;
	int segno;
	int err = 0;
    unsigned char *buffer;
    struct bio_vec *bvec;
	

    buffer = (unsigned char*) vmalloc(bio->bytes_n);//will be vfree when it's poped.
    
    if(!buffer){
		err = -1;
        goto OUT;
    }

    __bio_for_each_segment(bvec,bio,segno,0){
        memcpy((void*)(buffer + calc_size),page_address(bvec->bv_page) + bvec->bv_offset,bvec->bv_len);
        calc_size += bvec->bv_len;
    }
	_rb_entry->bf_ptr = buffer;
	
OUT:
	return err;
}



/*
 * mtrace_interface
 * @bio-the bio that is finished.
 */
void mtrace_bio_collect(struct bio *bio)
{
	struct rb_data entry;
	struct mtrace *_m = &m1;
	struct simple_ring_buf *_rbf = &rb1;
	int err;
	
	if(bio->bytes_n && MTRACE_STARTED(_m))/*is the target device?*/
	{
#ifdef MTRACE_DEBUG_ON
		printk(KERN_INFO "[mtrace] - collected.\n");
#endif
    	mtrace_get_bio_meta(bio, &(entry.mt));
    	err = mtrace_bio_remain(bio, &entry);
		if(err){
			printk(KERN_ERR "[mtrace] - mtrace_bio_remain error.\n");
			return;
		}
		err = srb_push_shallow(_rbf, &entry);
		if(err){
			printk(KERN_ERR "[mtrace] - srb_push_uninterruptable_shallow error : ring buffer full, vfree the buffer.\n");
			vfree(entry.bf_ptr);
			return;
		}
    	wake_up(&wq);
	}
}



/*
 *	when recieving "stop" command from user-space, stop the tracing job and inform the user-space program.
 */
static void mtrace_stop_uninterruptable(struct mtrace *_m)
{
	if(MTRACE_STARTED(_m)){
		MTRACE_SET_STOPED(_m);
	}
}

/*
 *  start tracing job - plant the probe
 */
static void mtrace_start_uninterruptable(struct mtrace *_m, __u32 _uid)
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
		mtrace_start_uninterruptable(_m,  nlh->nlmsg_pid);
        spin_unlock(&mtrace_lck);

		wake_up_process(_m->task_rm);
		printk(KERN_INFO "[mtrace] - going to start trace - %d.\n", _m->state);
    }

    if(0 == strcmp(buf, "stop") && MTRACE_STARTED(_m)){
        spin_lock(&mtrace_lck);
        mtrace_stop_uninterruptable(_m);
        spin_unlock(&mtrace_lck);
		
		mtrace_send_msg(_m, "exit");//cannot send msg inside a lock
        printk(KERN_INFO "[mtrace] - going to stop trace - %d.\n", _m->state);
    }
}

void _mtrace_sock_release(struct mtrace *_m)
{
    if(_m->nl_mtrace_fd){
        netlink_kernel_release(_m->nl_mtrace_fd);
    }
}





/*
 *  this thread do the remained jobs.
 */
static int thread_func_rm(void *data)
{
	struct mtrace *_m = &m1;
	struct simple_ring_buf *_rbf = &rb1;
#ifdef MTRACE_DEBUG_ON
	printk(KERN_INFO "[mtrace] - task_rm kthread start.\n");
#endif	
    while(1){
         /* do buf pop job */
        if(-1 == srb_pop_all(_rbf)){
            printk(KERN_INFO "[mtrace] - srb empty.\n");
        }
		if(MTRACE_RELEASED(_m)){ break; }//let's stop the thread.
        wait_event(wq, srb_not_empty(_rbf)); //wait until the buffer is not empty & pop it out.
    }
#ifdef MTRACE_DEBUG_ON
	printk(KERN_INFO "[mtrace] - task_rm kthread stop.\n");
#endif
	return 0;
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
	
	//if sock init good, here we go.
	_m->task_rm = kthread_create(thread_func_rm, NULL, "task_rm_thread");
	if(IS_ERR(_m->task_rm)){
		MTRACE_SET_ERR_BIT(Err, E_KTHREAD_INIT);
    	printk(KERN_ERR "[mtrace] - create task_rm thread error.\n");
		goto CLEAN_SOCK;
	}else{
		printk(KERN_INFO "[mtrace] - create kernel thread success.\n");
	}


	//if sock init good & kthread init good, SET INITED & go.
	MTRACE_SET_INITED(_m);
	printk(KERN_INFO "[mtrace] - init2 v3_for_functional.\n");
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
