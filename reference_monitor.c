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

#include "reference_monitor.h"
#define LINE_SIZE 256

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michele Tosi");
MODULE_DESCRIPTION("Questo modulo implementa un reference monitor come da specifiche presenti nel file README.md");

char *the_file = NULL;
module_param(the_file, charp, 0660);
MODULE_PARM_DESC(the_file, "Path to the log file");

char *module_name=NULL;
module_param(module_name, charp, 0660);
MODULE_PARM_DESC(module_name, "Module name");

static int major;

spinlock_t RM_lock;

static int rm_open(struct inode *inode, struct file *filp);

static ssize_t rm_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);

rm_config config;

// Mappa dei nomi degli stati
static const char *status_names[] = {
    [ON] = "\"start\"",
    [OFF] = "\"stop\"",
    [REC_ON] = "\"reconfig_on\"",
    [REC_OFF] = "\"reconfig_off\""
};

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
	int ret;
	char *buffer, *cmd, *password, *new_password,*p, *path;
	
	if(count>=LINE_SIZE){
		printk(KERN_ERR "%s: input lenght too large", MOD_NAME);
		return -EINVAL;
	}
	
	// alloco spazio per il buffer che conterrà in input il comando utente
	buffer=kmalloc(LINE_SIZE, GFP_KERNEL);
	if(!buffer){
		printk(KERN_ERR "%s: Errore nell'allocazione della memoria per il buffer in rm_write", MOD_NAME);
		return -ENOMEM;
	}
	
	ret=copy_from_user(buffer, buf, count);
	if(ret){
		printk(KERN_ERR "%s: errore nella copia dei dati, %d byte non copiati\n", MOD_NAME, ret);
		return -EFAULT;
	}
	
	//separo i comandi nell'input utente
	cmd=strsep(&buffer, " ");
	if(strcmp(cmd, "ref_monitor")){
		printk(KERN_INFO "%s: Il primo elemento del comando deve essere \"ref_monitor\"", MOD_NAME);
		return -EACCES;
	}
	cmd=strsep(&buffer, " ");
	
	if(strcmp(cmd, "add-path") == 0 || strcmp(cmd, "remove-path") == 0){
		path=strsep(&buffer, " ");
		printk(KERN_INFO "path_ : %s", path);
	}
	
	//cerco all'interno della stringa di input utente il punto in cui inizia la password -p
	password=strnstr(buffer, "-p ", strlen(buffer));
	//faccio partire la password 4 caratteri dopo escludendo '-p "'
	password+=4;
	//tolgo la virgoletta posta come ultimo carattere
	password[strlen(password)-1]='\0';
	
	if((new_password=strnstr(buffer, "-np ", strlen(buffer)))){
		new_password+=5;
		p=strnstr(buffer, " -p", strlen(buffer));
		*(--p)='\0';
	}
	
	printk(KERN_INFO "Password inserita in input: %s\n", password);
	
	//password=obtain_password();
	if(!verify_password(password)){
		printk(KERN_INFO "verificando la password..\n");
		return -EACCES;
	}
	
	printk(KERN_INFO "%s: password: %s, new_password: %s, comando: %s\n", MOD_NAME, password, new_password, cmd);
	
	if (strcmp(cmd, "start") == 0) {
        rm_on();
    } else if (strcmp(cmd, "stop") == 0) {
        rm_off();
    } else if (strcmp(cmd, "reconfig_on") == 0) {
        rm_rec_on();
    } else if (strcmp(cmd, "reconfig_off") == 0) {
        rm_rec_off();
    } else if (strcmp(cmd, "status") == 0) {
        printk("status corrente %s",status_names[config.rm_state]);
    } else if (strcmp(cmd, "set-password") == 0) {
    	set_password(new_password);
    } else if (strcmp(cmd, "add-path") == 0) {
        add_path(path);  // Pass the second argument (path)
    } else if (strcmp(cmd, "remove-path") == 0) {
        rm_path(path);  // Pass the second argument (path)
    } else {
        printk("Unknown cmd: %s\n", cmd);
        return -EINVAL;
    }
	
	
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

	//registro le kretprobes
    if((ret=register_probes())){
    	return ret;
    }

	//inizialmente il reference monitor ha stato OFF e le kretprobe sono disabilitate
    config.rm_state=OFF;
    disable_probes();
    
    printk(KERN_INFO "state corrente %d\n", config.rm_state);
    
    printk("%s: reference monitor module correctly loaded\n", MOD_NAME);
    
    printk(KERN_INFO "%s: prova get_abs %s ciao\n", MOD_NAME, get_absolute_path("utils.h"));

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
