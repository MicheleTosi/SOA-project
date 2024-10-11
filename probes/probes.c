#include <linux/kprobes.h>
#include <linux/slab.h>

#include "../utils/utils.h"
#include "../utils/constants.h"
#include "probes.h"


struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

struct kretprobe_data {
    int block_flag; // Flag per indicare se l'operazione deve essere bloccata
};

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

int register_probes(){
	int ret=0;
	
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
    
    printk(KERN_INFO "%s: kprobes registered\n", MOD_NAME);
    
    return ret;
	
}

void unregister_probes(){
	unregister_kretprobe(&kp_do_filp_open);
    unregister_kretprobe(&kp_do_unlinkat);
    unregister_kretprobe(&kp_do_mkdir);
    unregister_kretprobe(&kp_do_rmdir);
    
    printk(KERN_INFO "%s: kprobes unregistered\n", MOD_NAME);
    
}

void enable_probes(){
	enable_kretprobe(&kp_do_filp_open);
	enable_kretprobe(&kp_do_unlinkat);
	enable_kretprobe(&kp_do_mkdir);
	enable_kretprobe(&kp_do_rmdir);
}

void disable_probes(){
	disable_kretprobe(&kp_do_filp_open);
    disable_kretprobe(&kp_do_unlinkat);
    disable_kretprobe(&kp_do_mkdir);
    disable_kretprobe(&kp_do_rmdir);
}
