#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "path_list.h"
#include "../reference_monitor.h"

//controllo se nella lista è già presente il path passato in input
int check_list(char *abs_path){
	path_node *curr=config.head;
	
	if(curr==NULL){
		return 0;
	}

	printk("entrato in check_list");
	
	//scorro la lista di percorsi bloccati per vedere se è presente il path passato in input	
	while(curr){
		printk("path: %s abs_path: %s head: %s\n", curr->path, abs_path, config.head->path);
		if(strcmp(curr->path, abs_path)==0){
			printk(KERN_INFO "Path already exist %s\n", abs_path);
			return 1;
		}
		curr=curr->next;
	}
	
	return 0;
	
}

int add_path(char *path){
	
	char *abs_path=get_absolute_path(path);		//convert path to absolute path
	path_node *new_node;
	int res;
	
	if(!abs_path){
		printk(KERN_ERR "%s: could not resolve absolute path\n", MOD_NAME);
		return -EINVAL;
	}
	
	if(config.rm_state!=REC_ON && config.rm_state!=REC_OFF){
		printk(KERN_ERR "%s: state must be REC_ON or REC_OFF\n", MOD_NAME);
		return -EINVAL;
	}
	
	
	if(the_file && strncmp(abs_path, the_file, strlen(the_file))==0){
		printk(KERN_ERR "Error: cannot protect the log file path\n");
		return -EINVAL;
	}
	
	spin_lock(&RM_lock);
	
	if((res=check_list(path))){
		printk("path già presente %d\n", res);
		spin_unlock(&RM_lock);
		return res;
	}
	
	//Creation of the new node
    new_node = kmalloc(sizeof(struct path_node), GFP_KERNEL);
    if (!new_node) {
        printk(KERN_ERR "Failed to allocate memory for new node\n");
        spin_unlock(&RM_lock);
        return -ENOMEM;
    }
    //new_node->path = abs_path;
    new_node->path= kmalloc(strlen(abs_path)+1, GFP_KERNEL);
    strncpy(new_node->path, abs_path, strlen(abs_path)+1);
    new_node->next = config.head;
    config.head = new_node;

    spin_unlock(&RM_lock);

    printk(KERN_INFO "Path inserted: %s\n", abs_path);

    return 0;
	
}

int rm_path(char *path){
	char *abs_path=get_absolute_path(path);		//convert path to absolute path
	path_node *prev, *curr;
	
	prev=NULL;
	curr=config.head;
	
	if(!abs_path){
		printk(KERN_ERR "%s: could not resolve absolute path\n", MOD_NAME);
		return -EINVAL;
	}
	
	if(config.rm_state!=REC_ON && config.rm_state!=REC_OFF){
		printk(KERN_ERR "%s: state must be REC_ON or REC_OFF\n", MOD_NAME);
		return -EINVAL;
	}
	
	spin_lock(&RM_lock);
	
	printk(KERN_INFO "FINO QUIIII\n");
	
	if(!curr){
		return 0;
	}
	
	//se il nodo da eliminare è la testa della lista dei path bloccati
	if(strcmp(curr->path, abs_path)==0){
		config.head=curr->next;
		memset(curr->path,0,strlen(curr->path));
		kfree(curr->path);
		spin_unlock(&RM_lock);	
		return 1;
	}
	
	//scorro la lista di percorsi bloccati per vedere se è presente il path passato in input	
	while(curr && !strcmp(curr->path, abs_path)){
		printk("eliminazione path: %s abs_path: %s head: %s\n", curr->path, abs_path, config.head->path);
		
		prev=curr;
		curr=curr->next;
	}
	
	if(!prev){
		spin_unlock(&RM_lock);
		return 0;
	}
		
	prev->next=curr->next;
	
	memset(curr, 0, sizeof(path_node));
	kfree(curr);
	
    spin_unlock(&RM_lock);

    printk(KERN_INFO "Path removed from list: %s\n", abs_path);

    return 1;
}
