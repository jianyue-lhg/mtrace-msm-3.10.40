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
 *  a ring-buf structure.
 *  
 */
static DEFINE_SPINLOCK(in_lock);

typedef struct data{
    bio_mt_t mt;                //meta data
    unsigned char *bf_ptr;      //data
    
    //...other fields...

}dt_t;

typedef struct my_ring_buf{
    dt_t buf[MY_RB_SIZE];
    int in;     //next idx to write in, need to be locked, here will be access by [bio_end_io] multi-producer
    int out;    //next idx to read out, ,here is only single-customer
}my_rb_t;

my_rb_t rbuf = {
    .in = 0,
    .out = 0,
};


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
/*
 *  send netlink msg to PID
 *  @message - the string to send
 *  @dstPID  - the destination pid
 */
void sendnlmsg(struct sock *_fd, char *message,__u32 dstPID)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int len = NLMSG_SPACE(MAX_MSGSIZE);
    int slen = 0;

    if(!message || !_fd){
        return;
    }

    skb = alloc_skb(len, GFP_ATOMIC);//GFP_ATOMIC 
    if(!skb){
        printk(KERN_ERR "[mtrace] - send msg: alloc_skb error.\n");
        return;
    }

    slen = strlen(message)+1;

    nlh = nlmsg_put(skb, 0, 0, 0, MAX_MSGSIZE, 0);

   // NETLINK_CB(skb).pid = 0;
    NETLINK_CB(skb).portid = 0;
    NETLINK_CB(skb).dst_group = 0;

    message[slen] = '\0';
    memcpy(NLMSG_DATA(nlh), message, slen+1);

    netlink_unicast(_fd, skb, dstPID, 1);//the last parameter - non-block is set to 1.
    //printk("send OK!\n");
    return;
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

void format2buf(char *buf, bio_mt_t *meta, char* _l)
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

void format2bufLong(char *buf, bio_mt_t *meta, char* _l, int seq)
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

void mtrace_form_trace(bio_mt_t *meta, int num_md5, unsigned char* md5)
{
    //send to userspace
    char outputbuff[OUTPUTBUFSIZE];
    char *md5str = (char *)kmalloc(((32 + 1) * num_md5) + 3, GFP_ATOMIC);
    char temp[OUTPUTONETIMESIZE];
    int ik, k, len, i;
    if(!md5str){
        return;
    }
    raw2md5str(num_md5, md5, md5str);
#ifdef MTRACE_DEBUG_ON
    printk(KERN_INFO "[mtrace] - Get a trace: %5ld.%-10ld,%c,%12lu,%10d,%15s,%s\n", 
                                meta->delay.tv_sec,
                                meta->delay.tv_nsec,
                                meta->RW,
                                meta->bi_sector,
                                (meta->bytes_n),
                                meta->comm,
                                md5str);
#endif

    if(num_md5 > 8){
        //large message 
        len = (32 + 1) * num_md5; 
        ik = 0; 
        i = 0;
        while(len > 0){
            k = len < OUTPUTONETIME ? len : OUTPUTONETIME;
            strncpy(temp ,md5str + ik, k);
            format2bufLong(outputbuff,  meta, temp, i);
            sendnlmsg(m1.nl_mtrace_fd, outputbuff, m1.uid);

            i++; ik += k; len -= k;
        }
    }else{
        format2buf(outputbuff, meta, md5str);
        sendnlmsg(m1.nl_mtrace_fd, outputbuff, m1.uid);
    }
	
//STOP:
    kfree(md5str);
}



/*
 *  push one I/O meta & I/O data into a bucket of the buf.
 *  @data_ptr - pointer to I/O data buf
 *  @meta_ptr - pointer to I/O meta structure
 *  @__rbuf - pointer to the ring buf
 *  there might be MORE than one kthread push into this buf, so a spin_lock is used.
 */
int myrb_push_uninterruptable(unsigned char *data_ptr, bio_mt_t *meta_ptr, my_rb_t *__rbuf)
{
    if(MY_RB_SIZE - __rbuf->in + __rbuf->out <= 0){
#ifdef MTRACE_DEBUG_ON
		printk(KERN_INFO "[mtrace] - rbuf full!\n");
#endif
        return -1;//rbuf full
    }
    spin_lock(&in_lock);
    /*data*/
    __rbuf->buf[__rbuf->in & (MY_RB_SIZE - 1)].bf_ptr = data_ptr;
    if(NULL != meta_ptr){
        /*other field*/
        __rbuf->buf[__rbuf->in & (MY_RB_SIZE - 1)].mt.delay.tv_sec = meta_ptr->delay.tv_sec;
        __rbuf->buf[__rbuf->in & (MY_RB_SIZE - 1)].mt.delay.tv_nsec = meta_ptr->delay.tv_nsec;
        __rbuf->buf[__rbuf->in & (MY_RB_SIZE - 1)].mt.RW = meta_ptr->RW;
        __rbuf->buf[__rbuf->in & (MY_RB_SIZE - 1)].mt.bi_sector = meta_ptr->bi_sector;
        __rbuf->buf[__rbuf->in & (MY_RB_SIZE - 1)].mt.bytes_n = meta_ptr->bytes_n;
        strncpy(__rbuf->buf[__rbuf->in & (MY_RB_SIZE - 1)].mt.comm, meta_ptr->comm, 15);
    }
    __rbuf->in += 1;
    spin_unlock(&in_lock);
    return 0;
}

/*
 *  pop all bucket out of the ring buf
 *  only one kthread(task_rm) do this job. 
 */
int myrb_pop_all(my_rb_t *__rbuf)
{
    int len = __rbuf->in - __rbuf->out;
    int idx;
    int numd5;
    unsigned char *md5list;

    if(len <= 0){
        return -1;//rbuf empty
    }
    while(len){

        idx = __rbuf->out & (MY_RB_SIZE - 1);
        
        if(NULL != __rbuf->buf[idx].bf_ptr){
            /*
             * do sth. with the [buf bucket numbered idx]
             */
            numd5 = ((__rbuf->buf[idx].mt.bytes_n) >> 12);
            md5list = (unsigned char *)kmalloc((numd5 << 4), GFP_ATOMIC);
            if(!md5list){
                goto EMD5;
            }
            calc_md5_list_v2(__rbuf->buf[idx].mt.bytes_n, __rbuf->buf[idx].bf_ptr, md5list);//md5-value

            mtrace_form_trace(&(__rbuf->buf[idx].mt), numd5, md5list);

            kfree(md5list);
EMD5:
            vfree(__rbuf->buf[idx].bf_ptr);
        }
        __rbuf->out += 1;
        len--;
    }
    return 0;
}




/*
 *  return if the rbuf is empty.
 */
bool myrb_not_empty(my_rb_t *__rbuf)
{
    return __rbuf->in - __rbuf->out > 0;
}


/*
 *  this thread do the remained job after jprobe is done.
 */
static int thread_func_rm(void *data)
{
	struct mtrace *_m = &m1;
    while(1){
         /* do buf pop job */
        if(-1 == myrb_pop_all(&rbuf)){
            printk(KERN_INFO "[mtrace] - rbuf empty.\n");
        }
		if(MTRACE_RELEASED(_m)){ break; }//let's stop the thread.
        wait_event(wq, myrb_not_empty(&rbuf)); //wait until rbuf is not empty
    }
    printk(KERN_INFO "[mtrace] - task_rm kthread stop.\n");
    return 0;
}



void mtrace_get_bio_meta(struct bio *bio, bio_mt_t *ret)
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




void mtrace_bio_remain(struct bio *bio, bio_mt_t *mt)
{
    int calc_size = 0;
    unsigned char *buffer;
    struct bio_vec *bvec;
    int segno;

    buffer = (unsigned char*) vmalloc(bio->bytes_n);

    if(!buffer){
        return;
    }

    __bio_for_each_segment(bvec,bio,segno,0){
        memcpy((void*)(buffer + calc_size),page_address(bvec->bv_page) + bvec->bv_offset,bvec->bv_len);
        calc_size += bvec->bv_len;
    }

    myrb_push_uninterruptable(buffer, mt, &rbuf);
    wake_up(&wq);

    //vfree(buffer); // will let ring buffer to vfree buffer
}

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

	//if sock init good, here we go.
	_m->task_rm = kthread_create(thread_func_rm, NULL, "task_rm_thread");
	if(IS_ERR(_m->task_rm)){
		MTRACE_SET_ERR_BIT(Err, E_KTHREAD_INIT);
    	printk(KERN_ERR "[mtrace] - create task_rm thread error.\n");
		goto CLEAN_SOCK;
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
