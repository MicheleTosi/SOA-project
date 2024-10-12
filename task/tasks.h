#ifndef TASKS_H
#define TASK_H

#include<linux/workqueue.h>

typedef struct rm_packed_work_deferred{
	pid_t tgid;						//TGID processo
	pid_t tid;						//ID thread
	uid_t uid;						//User ID
	uid_t euid;						//Effective User ID
	char *path;						//Percorso programma che si tenta di aprire
	u8 *content_hash;				//Hash del contenuto del file
	struct work_struct the_work;	//lavoro da svolgere in maniera differita
}rm_work_def;

void schedule_deferred_work(void);

#endif
