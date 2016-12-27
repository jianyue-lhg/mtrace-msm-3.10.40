#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <pthread.h>


#define NETLINK_MYTRACE 28

#define MSG_SEND_LEN 10
#define MSG_RECV_LEN 4096

#define ERR_ARGV		11
#define ERR_FILE		12
#define ERR_SOCK_ALLOC	13
#define ERR_SOCK_BIND 	14
#define ERR_THREAD 		15
#define ERR_NLH_ALLOC 	16
#define ERR_MSG_SEND 	17
#define ERR_MSG_RECV	18

#define DEBUG_ON

struct mytrace{
	/*settings*/
	char *m_fout_name;	//file name output into
	FILE* m_fp;
	int m_secs;			//run how many second for test

	int verbose;

	/*run-time data*/
	unsigned long long m_trace_num;	//
	struct timeval m_startime;		//


	/*sock things*/
	int m_sockfd; 
	struct sockaddr_nl m_src_addr;
	struct sockaddr_nl m_dest_addr;	
	pid_t pid;
};


struct mytrace u_m1;//all zero

void usage()
{
	printf("usage: mytrace -o <filename> -w <secs> [-v]\n");
}


void mytrace_release(struct mytrace *_m)
{
	if(_m->m_fp)
		fclose(_m->m_fp);
	if(_m->m_sockfd > 0)
		close(_m->m_sockfd);/**/
}

void errsys(int err, char *errstr, struct mytrace *_m)
{
	switch(err){
		case ERR_ARGV:			//
			printf("invalid parameter: %s!\n", errstr);
			usage();
			break;
		case ERR_FILE:			//
			perror(errstr);
			break;
		case ERR_SOCK_ALLOC:	//
		case ERR_SOCK_BIND:		//
		case ERR_THREAD:		//
		case ERR_NLH_ALLOC:		//
		case ERR_MSG_SEND:		//
		case ERR_MSG_RECV:		// from the worker thread.
			perror(errstr);
			mytrace_release(_m);
			break;
	}
	exit(-1);
}

FILE* _file_setup(struct mytrace *_m)
{
	FILE *fp;
	fp = fopen(_m->m_fout_name, "w+");
	if(fp == NULL){
		errsys(ERR_FILE, "fopen error", _m);
	}
	_m->m_fp = fp;
	return fp;
}


int _alloc_sock()
{
	return socket(PF_NETLINK, SOCK_RAW, NETLINK_MYTRACE);
}

void _netlink_setup_partial(struct mytrace *_m)
{
	int err;
	_m->m_sockfd = _alloc_sock();
	if(_m->m_sockfd < 0){
		goto ALLOC_ERR;
	}
	
	/*set destination*/
	memset(&(_m->m_dest_addr), 0, sizeof(struct sockaddr_nl));
	_m->m_dest_addr.nl_family = AF_NETLINK;
	_m->m_dest_addr.nl_pid = 0;
	_m->m_dest_addr.nl_groups = 0;

	/*set source*/
	memset(&(_m->m_src_addr), 0, sizeof(struct sockaddr_nl));
	_m->m_src_addr.nl_family = AF_NETLINK;
	_m->m_src_addr.nl_pid = _m->pid;/* self pid */

	err = bind(_m->m_sockfd, (struct sockaddr*)&(_m->m_src_addr), sizeof(struct sockaddr_nl));
	if(err){
		errsys(ERR_SOCK_BIND, "bind m_sockfd", _m);
	}
	return ;

ALLOC_ERR:
	errsys(ERR_SOCK_ALLOC, "sock alloc", _m);
}



void mytrace_init(struct mytrace *_m)
{
	_m->m_trace_num = 0;
	_m->pid = getpid();
	_file_setup(_m);
	_netlink_setup_partial(_m);
	gettimeofday(&(_m->m_startime), NULL);
}



void mytrace_arg_handle(struct mytrace* _m, int argc, char* argv[])
{
	int i;
	if(argc != 5){ errsys(ERR_ARGV, "bad parameters", _m); }
	for(i = 1;i < argc; i++)
	{
		if(argv[i][0] == '-'){
			switch(argv[i][1]){
				case 'o':
					_m->m_fout_name = argv[++i];
					break;
				case 'w':
					_m->m_secs = atoi(argv[++i]);
					break;
				case 'v':
					_m->verbose = 1;
				default:
					errsys(ERR_ARGV, argv[i], _m);
			}
		}else{
			errsys(ERR_ARGV, argv[i], _m);
		}
	}
}

void worker(struct mytrace *_m)
{
	struct nlmsghdr *nlh = NULL;	
	struct iovec iov;
	struct msghdr msg;
	int err;
	int reminder_thresolds = 10;
	/*work thread - data path*/

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MSG_RECV_LEN));
	if(nlh == NULL){
		errsys(ERR_NLH_ALLOC, "nlh alloc mem error", _m);
	}
	
	memset(nlh, 0, NLMSG_SPACE(MSG_RECV_LEN));
	nlh->nlmsg_len = NLMSG_SPACE(MSG_RECV_LEN);
	nlh->nlmsg_pid = _m->pid;
	nlh->nlmsg_flags = 0;

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	msg.msg_name = (void *)&(_m->m_dest_addr);
	msg.msg_namelen = sizeof(struct sockaddr_nl);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	

	while(1){
		err = recvmsg(_m->m_sockfd, &msg, 0);
		if(err < 0){
			errsys(ERR_MSG_RECV, "recvmsg", _m);
		}
		
		if(_m->verbose){		
			printf("[mtrace user] recv - %s\n", (char *)NLMSG_DATA(nlh));
		}

		if(strcmp((char *)NLMSG_DATA(nlh),"exit") == 0){
            break;
		}
		_m->m_trace_num++;
		fprintf(_m->m_fp,"%s\n",(char *)NLMSG_DATA(nlh));

		/*print some reminder info*/
		if(_m->m_trace_num > reminder_thresolds){
			printf("[mtrace user] I've recv %d traces.\n", reminder_thresolds);
			reminder_thresolds *= 2;
		}
	}
	printf("[mtrace user] worker exit.\n");
}

void send_to_kern(struct mytrace *_m, char* cmd)
{
	int err;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	struct msghdr msg;
#ifdef DEBUG_ON
	printf("[mtrace user] sending msg's length: %d\n", strlen(cmd));
#endif	
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MSG_SEND_LEN));
	if(nlh == NULL){
		errsys(ERR_NLH_ALLOC, "nlh alloc mem error", _m);
	}

	memset(nlh, 0, NLMSG_SPACE(MSG_SEND_LEN));

	nlh->nlmsg_len = NLMSG_SPACE(MSG_SEND_LEN);
	nlh->nlmsg_pid = _m->pid;
	nlh->nlmsg_type = NLMSG_NOOP;
	nlh->nlmsg_flags = 0;

	strcpy((char *)NLMSG_DATA(nlh), cmd);

	
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0 ,sizeof(msg));//bugfix: http://blog.chinaunix.net/uid-14327709-id-3037069.html

	msg.msg_name = (void *)(&(_m->m_dest_addr));
	msg.msg_namelen = sizeof(struct sockaddr_nl);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	err = sendmsg(_m->m_sockfd, &msg, 0);
	if(err < 0){
		errsys(ERR_MSG_SEND, "sendmsg", _m);
	}else{
		printf("[mtrace user] send ok!\n");
	}
	//free(nlh);
}

void trace_begin(struct mytrace *_m)
{
	struct timeval now;
	pthread_t worker_thread;
	int err;

	/*setup tracer worker*/
	printf("[mtrace user] start work thread.\n");
	err = pthread_create(&worker_thread, NULL, (void *)(&worker), _m);
	if(err){
		errsys(ERR_THREAD, "pthread_create", _m);
	}

	/*send cmd to start up tracer*/
	send_to_kern(_m, "start\0");

	while(1){
		/*here is a timer*/
		sleep(5);
		gettimeofday(&now, NULL);
		if(now.tv_sec - _m->m_startime.tv_sec > _m->m_secs){
			printf("[mtrace user] stop mytracer getting out of loop.\n");
            goto TIMEUP;
			break;
		}
	}

TIMEUP:
	printf("[mtrace user] stop mytracer get out of loop.\n");
	send_to_kern(_m, "stop\0");
	err = pthread_join(worker_thread, NULL);
	if(err){
		errsys(ERR_THREAD, "wait for worker error", _m);
	}
	printf("[mtrace user] %lld events.\n",_m->m_trace_num);
}


int main(int argc, char* argv[])
{
	memset(&u_m1, 0, sizeof(struct mytrace));
	mytrace_arg_handle(&u_m1, argc, argv);
#ifdef DEBUG_ON
	printf("[mtrace user] file_output: %s, wait: %d\n", u_m1.m_fout_name , u_m1.m_secs);
#endif
	mytrace_init(&u_m1);
	trace_begin(&u_m1);
	mytrace_release(&u_m1);
    return 0;
}
