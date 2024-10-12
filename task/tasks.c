#include "tasks.h"
#include "../utils/constants.h"
#include "../crypto/sha256.h"

int tupla_data_to_buffer(rm_work_def *data, char *buffer){
	int written, buf_size;
	
	//77 è la lunghezza della stringa esclusi i dati presi da data
	buf_size=2*sizeof(pid_t)+2*sizeof(uid_t)+PATH_MAX+HASH_SIZE+78;
	
	//concateno i dati della struttura di work deferring all'interno del buffer
	 written = snprintf(buffer, buf_size, "TGID: %d | PID: %d | UID: %d | EUID: %d | Program Path: %s | Program hashed content: %s \n",
                       data->tgid, 
					   data->tid, 
					   data->uid, 
					   data->euid,
                       data->path, 
					   u8_to_string(data->content_hash));
					   
	if(written<0 || written>=buf_size){
		return false; //errore, o buffer troppo piccolo
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
		printk(KERN_ERR "%s: errore nell'apertura di the_file: %ld\n", MOD_NAME, PTR_ERR(file));
		return false
	}
	
	ret = kernel_write(file,line, strlen(line),&pos);
	
	//se la scrittura non va a buon fine chiudo il file e ritorno false
	if(ret<0){
		printk(KERN_ERR "%s: scrittura fallita sul file \"the_file\"", MOD_NAME);
		filp_close(file, NULL);
        return false;
	}
	
	
	//se la scrittura è stata parziale riprova a scrivere i dati mancanti partendo dalla posizione a cui si è arrivati
	if (ret < strlen(line)) {
		printk(KERN_INFO "%s: sono stati scritti solo %d bytes", MOD_NAME, ret);
		kernel_write(file,line+ret, strlen(line)-ret,&pos);
	}

    printk(KERN_INFO "%s: File \"the_file\", scritta la linea: %s\n", MOD_NAME, line);
    
    //Chiusura del file
    filp_close(file, NULL);
  
    return true;
	
}

void do_deferred_work(struct work_struct *work){
	unsigned char *buffer; //buffer per leggere blocchi
	struct file *filp;
	char *line;
	rm_work_def *data=container_of(work, rm_work_def, work);
	
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
	
	if (concatenate_record_to_buffer(data, line)) {
		if (!write_append_only(line)) {
		    printk(KERN_ERR "%s: Operazione di scrittura in append only fallita\n", MOD_NAME);
		}
	}
	
	kfree(data->content_hash);
	kfree(line);	
	
}

