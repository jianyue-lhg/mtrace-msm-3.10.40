#ifndef MTRACE_H
#define MTRACE_H


#include <linux/types.h>
#include <linux/kernel.h>

#include <net/sock.h>           //
#include <linux/netlink.h>		//

#include <linux/time.h>			//struct timespec
#include <linux/bio.h>          //struct bio

struct mtrace{
	int has_inited;
	int state;
	struct sock *nl_mtrace_fd;
	struct task_struct *task_rm;

	struct timespec start_time;
    __u32 uid;
};

#define E_SOCK_INIT 1 
#define E_KTHREAD_INIT 2

#define MTRACE_STAT_STOP 0
#define MTRACE_STAT_START 1

#define MTRACE_STARTED(mptr) ((mptr)->state == MTRACE_STAT_START)
#define MTRACE_STOPED(mptr) (!(MTRACE_STARTED(mptr)))
#define MTRACE_SET_STARTED(mptr) do{ (mptr)->state = MTRACE_STAT_START; }while(0)
#define MTRACE_SET_STOPED(mptr) do{ (mptr)->state = MTRACE_STAT_STOP;}while(0)


#define MTRACE_CLEAR_ERR(Err) do{ Err = 0; }while(0)
#define MTRACE_SET_ERR_BIT(Err, bit) do{ Err |= 1<< (bit); }while(0)


#define MTRACE_INITED(mptr) ((mptr)->has_inited)
#define MTRACE_RELEASED(mptr) (!MTRACE_INITED(mptr))

#define MTRACE_UNINITED 0

#define MTRACE_SET_INITED(mptr) do{ (mptr)->has_inited = 1; }while(0)
#define MTRACE_UNSET_INITED(mptr) do{ (mptr)->has_inited = 0; }while(0)


#define MTRACE_SOCK_INITED(mptr) ((mptr)->nl_mtrace_fd)
#define MTRACE_SOCK_RELEASED(mptr) (!MTRACE_INITED(mptr))



typedef struct meta{
    struct timespec delay;  //delay
    char RW;                //RW
    unsigned long bi_sector;
    unsigned int bytes_n;
    char comm[18];
}bio_mt_t;

#endif