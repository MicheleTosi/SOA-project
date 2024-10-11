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


#include "constants.h"
#include "sha256.h"
#include "utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michele Tosi");
MODULE_DESCRIPTION("Questo modulo implementa un reference monitor come da specifiche presenti nel file README.md");


// Enumerazione per gli stati del reference monitor
typedef enum reference_monitor_state {
    ON,             // Operazioni abilitate
    OFF,            // Operazioni disabilitate
    REC_ON,         // Può essere riconfigurato in modalita' ON
    REC_OFF,        // Può essere riconfigurato in modalita' OFF
}rm_state;

//nodi path bloccati
typedef struct path_node{
	char *path;
	struct path_node *next;
}path_node;

// Configurazione attuale reference monitor
typedef struct reference_monitor_config {
    rm_state rm_state;                      // Stato corrente reference monitor
    u8 password[PASSWORD_HASH_SIZE];		// Password per riconfigurare il reference monitor
    path_node *head;     					// Lista path non accessibili in scrittura
} rm_config;

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};



static int major;

static int rm_open(struct inode *inode, struct file *filp);

static ssize_t rm_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);

static int handler_pre_do_filp_open(struct kretprobe_instance *kp, struct pt_regs *regs);

static int handler_pre_do_mkdirat(struct kretprobe_instance *kp, struct pt_regs *regs);

static int handler_pre_rm(struct kretprobe_instance *kp, struct pt_regs *regs);

static int post_handler(struct kretprobe_instance *kp, struct pt_regs *regs);

static spinlock_t RM_lock;

struct file_operations my_fops = {
    .owner=THIS_MODULE,
    .open = rm_open,
    .write = rm_write,
};

struct kretprobe_data {
    int block_flag; // Flag per indicare se l'operazione deve essere bloccata
};

static struct kretprobe kp_do_filp_open = {
    .kp.symbol_name=DO_FILP_OPEN,
    .data_size = sizeof(struct kretprobe_data), // Dimensione dei dati
    .entry_handler= handler_pre_do_filp_open,
    .handler=post_handler
};

static struct kretprobe kp_do_rmdir = {
    .kp.symbol_name=DO_RMDIR,
    .data_size = sizeof(struct kretprobe_data), // Dimensione dei dati
    .entry_handler=handler_pre_rm,
    .handler=post_handler
};

static struct kretprobe kp_do_mkdir = {
    .kp.symbol_name=DO_MKDIRAT,
    .data_size = sizeof(struct kretprobe_data), // Dimensione dei dati
    .entry_handler= handler_pre_do_mkdirat,
    .handler=post_handler
};

static struct kretprobe kp_do_unlinkat = {
    .kp.symbol_name = DO_UNLINKAT,
    .data_size = sizeof(struct kretprobe_data), // Dimensione dei dati
    .entry_handler=handler_pre_rm,
    .handler=post_handler
};

static rm_config config;

void change_rm_state(rm_state state);


int rm_on(void){

    change_rm_state(ON);

    return 0;
}

int rm_off(void){

    change_rm_state(OFF);

    return 0;
}

int rm_rec_on(void){

    change_rm_state(REC_ON);

    return 0;
}

int rm_rec_off(void){

    change_rm_state(REC_OFF);

    return 0;
}

void change_rm_state(rm_state state){
    rm_state current_state;
    
    printk("%s: changing reference monitor state\n", MOD_NAME);

	spin_lock(&RM_lock);	
	
	current_state=config.rm_state;

    printk("%s: initial state is %d\n", MOD_NAME, current_state);

    if((current_state==OFF || current_state==REC_OFF) && (state==ON || state==REC_ON)){

        //TODO: attivare il rm
        enable_kretprobe(&kp_do_filp_open);
		enable_kretprobe(&kp_do_unlinkat);
		enable_kretprobe(&kp_do_mkdir);
		enable_kretprobe(&kp_do_rmdir);

    }else if ((current_state==ON || current_state==REC_ON) && (state==OFF || state==REC_OFF)){

        //TODO: disattivare il rm
        /*disable_kretprobe(&kp_do_filp_open);
    	disable_kretprobe(&kp_do_unlinkat);
    	disable_kretprobe(&kp_do_mkdir);
    	disable_kretprobe(&kp_do_rmdir);*/

    }

    config.rm_state=state;

    printk("%s: new state is %d\n", MOD_NAME, config.rm_state);
    spin_unlock(&RM_lock);

    return;
}

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

static int post_handler(struct kretprobe_instance *kp, struct pt_regs *regs){
	struct kretprobe_data *data;
	data = (struct kretprobe_data *)kp->data;

	if (data->block_flag) {
        // Imposta il codice di errore per bloccare l'operazione
        regs->ax = -EACCES;
        data->block_flag = 0; // Reset del flag
        printk(KERN_INFO "%s: Operation blocked by kretprobe\n",MOD_NAME);
    }


	return 0;
}

//						di						si					dx					cx
//int vfs_mkdir(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, umode_t mode)
static int handler_pre_do_mkdirat(struct kretprobe_instance *kp, struct pt_regs *regs) {
    struct dentry *dentry, *parent_dentry;
    struct inode *inode;
    char *buf;
    char *name, *parent, *directory;
    
    struct kretprobe_data *data;
	data  = (struct kretprobe_data *)kp->data;
    
    name = (char *)((struct filename *)(regs->si))->name;

    if (IS_ERR(name)) {
        pr_err(KERN_ERR "%s: Error in get filename\n",MOD_NAME);
        return 0;
    }
    
    if (temp_file(name)) {
        return 0;
    }
    
    directory=get_absolute_path(name);
    printk("creazione %s\n", directory);
	if (directory == NULL) { /*se sto creando un file (quindi abs_path nullo) */
        	// Recupera il percorso della directory genitore del file
        	parent = get_dir_parent((char *)name);

        	// Recupera il percorso assoluto della directory genitore
        	directory = get_absolute_path(parent);

        	// Usa il percorso assoluto della directory genitore se è valido
        	if (directory == NULL) {
            	// Se il percorso assoluto non è valido, usa la directory corrente come fallback
           		directory = get_cwd();
        	}
	}

    printk(KERN_INFO "Attempt to create directory: %s\n", directory);

    spin_lock(&RM_lock);
    while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0) {

        if (check_list(directory)) {

			data->block_flag=1; //flag per bloccare l'operazione
            printk(KERN_ERR "%s: path or its parent directory is in blacklist: %s\n",MOD_NAME, directory);
            
            // Blocca l'operazione modificando il valore dei registri
			regs->ax = -EPERM;
			regs->di = (unsigned long)NULL;


            printk(KERN_ERR "%s: mkdir operation was blocked: %s\n",MOD_NAME, name);
			spin_unlock(&RM_lock);
            return 0;
        }

        // Ottieni la directory genitore
        directory = get_dir_parent(directory);
    }
	spin_unlock(&RM_lock);
    return 0;
}

/* struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};*/
/* struct filename {
	const char		*name;	// pointer to actual string 
	const __user char	*uptr;	// original userland pointer
	int			refcnt;
	struct audit_names	*aname;
	const char		iname[];
};*/
//								di				si						dx
// struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);
//uso la do_filp_open perché quando vfs_open utilizzato il file già potrebbe essere stato creato
static int handler_pre_do_filp_open(struct kretprobe_instance *kp, struct pt_regs *regs) {
    int fd;
    struct open_flags *op;
    const char *path_kernel, *path_user;
    char *directory, *parent;
    int flags;
    
    struct kretprobe_data *data;
	data  = (struct kretprobe_data *)kp->data;
    
    fd=regs->di;
    op=(struct open_flags *)(regs->dx);
    flags=op->open_flag;
    path_kernel = ((struct filename *)(regs->si))->name;
    path_user = ((struct filename *)(regs->si))->uptr;
    
    if(strncmp(path_kernel, "/run", 4) == 0) {
    	return 0;
    }
    
    directory=get_absolute_path(path_kernel);
    printk("user path: %s\n", path_kernel);
    printk("user path: %s\n", directory);

    // Logica per decidere se bloccare l'operazione
    
    //se il file è aperto in lettura, ritorno 	
	if(!(flags & O_RDWR) && !(flags & O_WRONLY) && !(flags & (O_CREAT | __O_TMPFILE | O_EXCL )))  return 0;

	if(flags & O_CREAT){
		printk("creazione %s\n", directory);
		if (directory == NULL) { /*se sto creando un file (quindi abs_path nullo) */
            	// Recupera il percorso della directory genitore del file
            	parent = get_dir_parent((char *)path_kernel);

            	// Recupera il percorso assoluto della directory genitore
            	directory = get_absolute_path(parent);

            	// Usa il percorso assoluto della directory genitore se è valido
            	if (directory == NULL) {
                	// Se il percorso assoluto non è valido, usa la directory corrente come fallback
               		directory = get_cwd();
            	}
		}
	}
	
	spin_lock(&RM_lock);
	
	while (directory && *directory && strcmp(directory, " ") != 0){ //controllo che sia non NULL e non vuoto.
	
		printk("Entrato");
		if(check_list(directory)){
			data->block_flag=1;
			printk(KERN_INFO "Bloccata scrittura su file vietato %s.\n", directory);
			op->open_flag = O_RDONLY;
			spin_unlock(&RM_lock);
            return 0;
		}
        printk("dir %s\n", directory);
		directory = get_dir_parent(directory); //itero sui parent della directory passata
	}

	spin_unlock(&RM_lock);
    return 0;
}

// si: struct inode*
// dx: struct dentry *
static int handler_pre_rm(struct kretprobe_instance *kp, struct pt_regs *regs) {
    struct dentry *dentry;
    char *buf;
    char *name, *directory;
    struct kretprobe_data *data;

	data  = (struct kretprobe_data *)kp->data;
	dentry = (struct dentry *)regs->dx;

	name = (char *)((struct filename *)(regs->si))->name;

    if (IS_ERR(name)) {
        pr_err(KERN_ERR "%s:Errore nell'ottenere il nome del file\n", MOD_NAME);
        return 0;
    }
    
    printk(KERN_INFO "%s: Attempt to remove file/directory: %s\n", MOD_NAME, name);
    
	//se temp-file nop
	if(temp_file(name)){
        kfree(buf);
		return 0;
	}
	
	//percorso assoluto
	directory=get_absolute_path(name);
	if(!directory){
		return 0;
	}
    
	//controlla se path presente nella lista dei file bloccati
	spin_lock(&RM_lock);
    while (directory != NULL && strcmp(directory, "") != 0 && strcmp(directory, " ") != 0) {

        if (check_list(directory)) {

			data->block_flag=1; //flag per bloccare l'operazione
            printk(KERN_ERR "%s: path or its parent directory is in blacklist: %s\n",MOD_NAME, directory);
            
            // Blocca l'operazione modificando il valore dei registri
			regs->ax = -EPERM;
			regs->di = (unsigned long)NULL;


            printk(KERN_ERR "%s: rmdir/unlinkat operation was blocked: %s\n",MOD_NAME, name);
			spin_unlock(&RM_lock);
            return 0;
        }

        // Ottieni la directory genitore
        directory = get_dir_parent(directory);
    }
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
    
    add_path("/home/vboxuser/Scrivania/prova");
    
    printk("curr_node %s\n", config.head->path);
    if(verify_password("password1", strlen("password1"), config.password)){
    	printk(KERN_INFO "la password corrisponde");
    }
    

    ret = register_kretprobe(&kp_do_filp_open);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe do_filp_open failed, returned %d\n", ret);
        return ret;
    }

	ret = register_kretprobe(&kp_do_unlinkat);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe vfs_unlink failed, returned %d\n", ret);
        unregister_kretprobe(&kp_do_filp_open);
        return ret;
    }

    ret = register_kretprobe(&kp_do_mkdir);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe vfs_mkdir failed, returned %d\n", ret);
        unregister_kretprobe(&kp_do_filp_open);
        unregister_kretprobe(&kp_do_unlinkat);
        return ret;
    }

    ret = register_kretprobe(&kp_do_rmdir);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe vfs_rmdir failed, returned %d\n", ret);
        unregister_kretprobe(&kp_do_filp_open);
        unregister_kretprobe(&kp_do_unlinkat);
        unregister_kretprobe(&kp_do_mkdir);
        return ret;
    }

    printk(KERN_INFO "kprobes registered\n");

    printk("%s: reference monitor module correctly loaded\n", MOD_NAME);
    
    printk(KERN_INFO "%s: prova get_abs %s ciao\n", MOD_NAME, get_absolute_path("utils.h"));
    
    // Registra la kprobe
    // Inizializzare deferred workqueue

    return 0;
}

static void my_module_exit(void) {

    unregister_kretprobe(&kp_do_filp_open);
    unregister_kretprobe(&kp_do_unlinkat);
    unregister_kretprobe(&kp_do_mkdir);
    unregister_kretprobe(&kp_do_rmdir);

    printk("%s: reference monitor module unloaded\n", MOD_NAME);
    
    unregister_chrdev(major, DEV_NAME);
	printk(KERN_INFO "%s: device unregistered, it was assigned major number %d\n",DEV_NAME,major);
    
}

module_init(my_module_init)
module_exit(my_module_exit)
