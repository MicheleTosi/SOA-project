#include<linux/cred.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kernel.h>

#include "tasks.h"
#include "../utils/constants.h"
#include "../crypto/sha256.h"
#include "../reference_monitor.h"
#include "../utils/utils.h"

//78 è la lunghezza della stringa esclusi i dati presi da data
#define RECORD_SIZE 2*sizeof(pid_t)+2*sizeof(uid_t)+PATH_MAX+HASH_SIZE+78 

int tupla_data_to_buffer(rm_work_def *data, char *buffer){
	int written;
	
	//concateno i dati della struttura di work deferring all'interno del buffer
	 written = snprintf(buffer, RECORD_SIZE, "TGID: %d | PID: %d | UID: %d | EUID: %d | Program Path: %s | Program hashed content: %s \n",
                       data->tgid, 
					   data->tid, 
					   data->uid, 
					   data->euid,
                       data->path, 
					   u8_to_string(data->content_hash));
					   
	if(written<0){
		return false; //errore
	}
	
	return true; //operazione andata a buon fine
}

bool write_append(char *buf){
	loff_t pos=0;
	int ret=0;
	struct file *file;
	
	//apro il file in modalità append only
	file=filp_open(the_file, O_WRONLY|O_APPEND, 0);
	if(IS_ERR(file)){
		printk(KERN_ERR "%s: errore nell'apertura di the_file\n", MOD_NAME);
		return false;
	}
	
	ret = kernel_write(file,buf, strlen(buf),&pos);
	
	//se la scrittura non va a buon fine chiudo il file e ritorno false
	if(ret<0){
		printk(KERN_ERR "%s: scrittura fallita sul file \"the_file\"", MOD_NAME);
		filp_close(file, NULL);
        return false;
	}
	
	
	//se la scrittura è stata parziale riprova a scrivere i dati mancanti partendo dalla posizione a cui si è arrivati
	if (ret < strlen(buf)) {
		printk(KERN_INFO "%s: sono stati scritti solo %d bytes", MOD_NAME, ret);
		kernel_write(file,buf+ret, strlen(buf)-ret,&pos);
	}

    printk(KERN_INFO "%s: File \"the_file\", scritta la linea: %s\n", MOD_NAME, buf);
    
    //Chiusura del file
    filp_close(file, NULL);
  
    return true;
	
}

void do_deferred_work(struct work_struct *work){
	struct file *filp;
	char *line;
	rm_work_def *data=container_of(work, rm_work_def, the_work);
	
	data->content_hash=kzalloc(HASH_SIZE, GFP_KERNEL);
	if(!data->content_hash){
		printk(KERN_ERR "%s: allocazione di memoria per l'hash fallita\n", MOD_NAME);
		return;
	}
	
	line=kzalloc(RECORD_SIZE, GFP_KERNEL);
	if(!line){
		printk(KERN_ERR "%s: allocazione di memoria per buffer fallita\n", MOD_NAME);
		kfree(data->content_hash);
		return;
	}
	
	filp=filp_open(data->path, O_RDONLY, 0);
	if(IS_ERR(filp)){
		printk(KERN_ERR "%s: fallimento nell'apertura del file eseguibile in lettura\n", MOD_NAME);
		kfree(line);
		kfree(data->content_hash);
		return;
	}
	
	if(!calculate_sha256_file_content(filp, data->content_hash)){
		printk(KERN_ERR "%s: calcolo dell'hash del contenuto dell'eseguibile fallito\n", MOD_NAME);
		kfree(line);
		kfree(data->content_hash);
		filp_close(filp,NULL);
		return;
	}
	
	//chiudo il file
	filp_close(filp, NULL);
	
	if (tupla_data_to_buffer(data, line)) {
		if (!write_append(line)) {
		    printk(KERN_ERR "%s: Operazione di scrittura in append only fallita\n", MOD_NAME);
		}
	}
	
	kfree(data->content_hash);
	kfree(line);	
	
}

void schedule_deferred_work(void){
	rm_work_def *the_task;
	
	struct cred *current_credentials;
	char *process_path;
	
	// Alloca memoria per i dati del task differito
	the_task=kzalloc(sizeof(rm_work_def), GFP_KERNEL);
	if(!the_task){
		printk(KERN_ERR "%s: Allocazione memoria non riuscita per il deferred task\n", MOD_NAME);
		return;
	}
	
	// Ottieni le credenziali del processo corrente
	current_credentials=(struct cred*) get_task_cred(current);
	
	// Popola la struttura con i dati del processo corrente
	the_task->tgid=current->tgid;
	the_task->tid=current->pid;
	the_task->uid=current_credentials->uid.val;
	the_task->euid=current_credentials->euid.val;
	
	// Ottieni il percorso del file eseguibile del processo corrente
	process_path=get_current_proc_path();
	if(IS_ERR(process_path)){
		printk(KERN_ERR "%s: errore nel recupero del path del processo\n", MOD_NAME);
		kfree(the_task);
		return;
	}
	
	the_task->path=kmalloc(PATH_MAX, GFP_KERNEL);
	
	// Copia il percorso nel campo path della struttura che gestisce le informazioni sul task
	strncpy(the_task->path, process_path, PATH_MAX);
	
	// Stampa le informazioni raccolte
    printk("schedule_deferred_task: pid %d, tgid %d, uid %d, euid %d, path %s\n",
           the_task->tid, 
		   the_task->tgid,
           the_task->uid, 
		   the_task->euid,
           the_task->path);
	
	// Inizializza il deferred work
	__INIT_WORK(&(the_task->the_work), do_deferred_work, (unsigned long)(&(the_task->the_work)));
	
	//Accoda il lavoro alla coda di lavoro
	schedule_work(&the_task->the_work);
	
}

