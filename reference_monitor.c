#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/printk.h>      
#include <linux/ptrace.h>       
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/dcache.h>


#include "utils/constants.h"
#include "crypto/sha256.h"
#include "utils/utils.h"
#include "probes/probes.h"
#include "reference_monitor.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michele Tosi");
MODULE_DESCRIPTION("Questo modulo implementa un reference monitor come da specifiche presenti nel file README.md");

char *the_file = NULL;
module_param(the_file, charp, 0660);
MODULE_PARM_DESC(the_file, "Path to the log file");

static int major;

spinlock_t RM_lock;

static int rm_open(struct inode *inode, struct file *filp);

static ssize_t rm_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);

rm_config config;

struct file_operations my_fops = {
    .owner=THIS_MODULE,
    .open = rm_open,
    .write = rm_write,
};

static int rm_open(struct inode *inode, struct file *filp)
{
    return 0;
}

static ssize_t rm_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    return 0;
}

//controllo se nella lista è già presente il path passato in input
int check_list(char *abs_path){
	path_node *curr=config.head;

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
	
	
	/*if(the_file && strncmp(abs_path, the_file, strlen(the_file))==0){
		printk(KERN_ERR "Error: cannot protect the log file path\n");
		return -EINVAL;
	}*/
	
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

int change_password(char *new_password){

    printk(KERN_INFO "%s: change password", MOD_NAME);
    
    if(!new_password){
    	printk(KERN_ERR "%s: empty password", MOD_NAME);
    	return -EINVAL; 
    }
    
    spin_lock(&RM_lock);
    
    calculate_sha256(new_password, strlen(new_password), config.password);
    
    printk(KERN_INFO "%s: password %s", MOD_NAME, config.password);
    
    printk(KERN_INFO "%s: password aggiornata correttamente", MOD_NAME);
    
    spin_unlock(&RM_lock);
    
    return 0;
    
}

static int my_module_init(void) {

    int ret;

    major=register_chrdev(0,DEV_NAME,&my_fops);

    if(major<0){
        printk(KERN_ERR "register_chrdev failed: %d\n", major);
        return major;
    }

    printk(KERN_INFO "%s: device \"%s\" registered with major number %d\n",MOD_NAME,DEV_NAME, major);

    // Calcola l'hash SHA-256 della password
    ret = calculate_sha256("password", strlen("password"), config.password);
    if (ret) {
        pr_err("Failed to calculate SHA-256 hash\n");
        return ret;
    }

    pr_info("SHA-256 hash of password calculated successfully\n");

    print_hash(config.password);

    rm_rec_off();
    
    printk(KERN_INFO "state corrente %d\n", config.rm_state);
    
    add_path("/home/vboxuser/Scrivania/prova");
    
    printk("curr_node %s\n", config.head->path);
    if(verify_password("password1", strlen("password1"), config.password)){
    	printk(KERN_INFO "la password corrisponde");
    }

    if(!(ret=register_probes())){
    	return ret;
    }

    printk("%s: reference monitor module correctly loaded\n", MOD_NAME);
    
    printk(KERN_INFO "%s: prova get_abs %s ciao\n", MOD_NAME, get_absolute_path("utils.h"));
    
    // Registra la kprobe
    // Inizializzare deferred workqueue

    return 0;
}

static void my_module_exit(void) {

    unregister_probes();

    unregister_chrdev(major, DEV_NAME);
	printk(KERN_INFO "%s: device unregistered, it was assigned major number %d\n",DEV_NAME,major);
 
 	printk("%s: reference monitor module unloaded\n", MOD_NAME);
    
}

module_init(my_module_init)
module_exit(my_module_exit)
