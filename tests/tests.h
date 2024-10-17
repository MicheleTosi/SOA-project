#ifndef TESTS
#define TESTS

#define LINE_SIZE 256

int run_test(int (*func)(void), char *password);
int create_test(void);
int open_test(void);
int unlink_test(void);
int mkdir_test(void);
int rmdir_test(void);

int setup(void);
int cleanup(char *path);

int check_if_module_is_inserted(void);

#endif
