#ifndef _UTILS_H
#define _UTILS_H

static spinlock_t RM_lock;

extern char *get_absolute_path(const char *filename);
extern char *get_dir_parent(char *path);
extern char* get_cwd(void);
extern int temp_file(char *name);

int check_list(char *abs_path);

int rm_on(void);
int rm_off(void);
int rm_rec_on(void);
int rm_rec_off(void);

#endif
