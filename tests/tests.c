#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>

#include "tests.h"

#define DEVICE_PATH "/dev/ref_monitor"

#define TEST_ROOT "/tmp/reference-monitor-tests"
#define TEST_DIRECTORY "/tmp/reference-monitor-tests/directory"
#define TEST_DIRECTORY_FILE "/tmp/reference-monitor-tests/directory/file.txt"
#define TEST_FILE "/tmp/reference-monitor-tests/file.txt"

int fd;
char cmd[PATH_MAX];

int main(void){
	char password[LINE_SIZE];
	
	//Check if module is loaded
	if(check_if_module_is_inserted()!=0)
		exit(EXIT_FAILURE);

	printf("Enter password: ");
	fgets(password, LINE_SIZE, stdin);
    	password[strcspn(password, "\n")]=0;
    	
	if(password==NULL){
		fprintf(stderr, "Failed to get password\n");
		return EXIT_FAILURE;
	}
	
	if (run_test(create_test, password) != 0) {
	    fprintf(stderr, "create test failed\n");
	    return EXIT_FAILURE;
	}
	if (run_test(open_test, password) != 0) {
		fprintf(stderr, "open test failed\n");
		return EXIT_FAILURE;
	}
	if (run_test(unlink_test, password) != 0) {
		fprintf(stderr, "unlink test failed\n");
		return EXIT_FAILURE;
	}
	if (run_test(mkdir_test, password) != 0) {
		fprintf(stderr, "mkdir test failed\n");
		return EXIT_FAILURE;
	}
	if (run_test(rmdir_test, password) != 0) {
		fprintf(stderr, "rmdir test failed\n");
		return EXIT_FAILURE;
	}

	puts("Tests were successful");
	return EXIT_SUCCESS;
	
}

//Attempts to create file or directory in protected directory
int create_test(void){
	//Create file in protected directory
	if(open("/tmp/reference-monitor-tests/directory/new.txt", O_CREAT | O_WRONLY, 0644)!=-1){
		fprintf(stderr, "Open was successful in create_test");
		return -1;
	}
	
	// Create new directory in protected directory
  	if (mkdir("/tmp/reference-monitor-tests/directory/new", 0755) == 0) {
   		fprintf(stderr, "mkdir was successful in create_test\n");
    		return -1;
  	}

  // Successful test
  return 0;

}

// Attemps to write a file in protected directory (should fail when trying to open it in write mode)
int open_test(void) {
	int fd2 = 0;
	char *text = "open_test";

	// Open protected file
	if ((fd2 = open(TEST_FILE, O_WRONLY, 0644)) == 1) {
		fprintf(stderr, "open for file in root failed in open_test\n");
		return -1;
	}
	
	if (write(fd2, text, strlen(text)) != -1) {
		fprintf(stderr, "write for file in root was successful in open_test\n");
		return -1;
	}

	// Open file in protected directory
	if ((fd2 = open(TEST_DIRECTORY_FILE, O_WRONLY, 0644)) == 1) {
		fprintf(stderr, "open for file in directory failed in open_test\n");
		return -1;
	}
	
	if (write(fd2, text, strlen(text)) != -1) {
		fprintf(stderr, "write for file in directory was successful in open_test\n");
		return -1;
	}
	
	return 0;
}

// Attempts to remove a protected file or file in a directory
int unlink_test(void) {

	if (unlink(TEST_DIRECTORY_FILE) == 0) {
		fprintf(stderr, "unlink for file.txt in directory was sucessful in unlink_test\n");
		return -1;
	}

	return 0;
}

// Attempts to create a directory in a protected directory
int mkdir_test(void) {
	if (mkdir("/tmp/reference-monitor-tests/directory/new", 0664) == 0) {
		fprintf(stderr, "mkdir was successful in mkdir_test\n");
		return -1;
	}
	return 0;
}

// Attempts to remove a protected directory
int rmdir_test(void) {
	if (rmdir(TEST_DIRECTORY) == 0) {
		fprintf(stderr, "rmdir was successful in rmdir_test\n");
		return -1;
	}
	return 0;
}

int run_test(int (*func)(void), char *password){
	int ret=0;
	//Setup environment
	if(setup()!=0){
		ret=-1;
		goto exit;
	}

	//Open device
	fd=open(DEVICE_PATH, O_WRONLY);
	if(fd<0){
		printf("Failed to open device\n");
		ret = -1;
		goto exit;
	}

	sprintf(cmd, "ref_monitor reconfig_on -p \"%s\"", password);
	//Set state to REC-ON
	if(write(fd, cmd, strlen(cmd))<0){
		perror("Failed to set state to REC-ON");
		ret=-1;
		goto exit;
	}

	sprintf(cmd, "ref_monitor add-path %s -p \"%s\"", TEST_DIRECTORY, password);
	//Add directory to protected paths
	if(write(fd, cmd, strlen(cmd))<0){
		perror("Failed to add directory to protected path");
		ret=-1;
		goto exit;
	}

	sprintf(cmd, "ref_monitor add-path %s -p \"%s\"", TEST_FILE, password);
	//Add file to protected paths
	if(write(fd, cmd, strlen(cmd))<0){
		perror("Failed to add file to protected paths");
		ret=-1;
		goto exit;
	}

	ret=func();
	
	sprintf(cmd, "ref_monitor remove-path %s -p \"%s\"", TEST_DIRECTORY, password);
	//Add directory to protected paths
	if(write(fd, cmd, strlen(cmd))<0){
		perror("Failed to remove directory to protected path");
		ret=-1;
		goto exit;
	}

	sprintf(cmd, "ref_monitor remove-path %s -p \"%s\"", TEST_FILE, password);
	//Add file to protected paths
	if(write(fd, cmd, strlen(cmd))<0){
		perror("Failed to remove file to protected paths");
		ret=-1;
		goto exit;
	}

	sprintf(cmd, "ref_monitor stop -p \"%s\"", password);
	//Set state OFF
	if(write(fd, cmd, strlen(cmd))<0){
		perror("Failed to set state to OFF");
		ret=-1;
		goto exit;
	}

exit:
	if(cleanup(TEST_ROOT)!=0)
		return -1;
	return ret;

}

int setup(void) {
  // Create root test directory
  if (mkdir(TEST_ROOT, 0755) != 0) {
    perror("Failed to setup test environment (mkdir root)");
    return EXIT_FAILURE;
  }

  // Create protected directory
  if (mkdir(TEST_DIRECTORY, 0755) != 0) {
    puts("Failed to setup test environment (mkdir test directory)");
    return EXIT_FAILURE;
  }

  // Create not protected file in protected directory
  if (open(TEST_DIRECTORY_FILE, O_CREAT | O_WRONLY, 0644) == -1) {
    puts("Failed to setup test environment (open file in directory)");
    return EXIT_FAILURE;
  }

  // Create protected file in root
  if (open(TEST_FILE, O_CREAT | O_WRONLY, 0644) == -1) {
    puts("Failed to setup test environment (open file)");
    return EXIT_FAILURE;
  }

  return 0;
}

int cleanup(char *path) {
  DIR *dir;
  struct dirent *entry;
  struct stat statstruct;
  char fullpath[PATH_MAX];

  // Try to open path as directory
  if ((dir = opendir(path)) == NULL) {
    // Not a directory, remove the file
    return unlink(path);
  }

  // Loop through files in directory
  while ((entry = readdir(dir)) != NULL) {
    // Skip . and ..
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;

    // Create full path
    snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

    // Check stats of path
    if (stat(fullpath, &statstruct) == 0) {
      if (S_ISDIR(statstruct.st_mode))
        cleanup(fullpath); // Cleanup directory recursively
      else
        unlink(fullpath); // Remove file
    }
  }

  closedir(dir); // Close directory

  return rmdir(path); // Cleanup directory
}


int check_if_module_is_inserted() {
	FILE *fp;
	char live[4];
	char *path = "/sys/module/ref_monitor/initstate";
	if (access(path, R_OK) != 0) {
		fprintf(stderr, "Module is not loaded\n");
		return -1;
	}	
	fp = fopen(path, "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to read module initstate");
		return -1;
	}
	fread(live, sizeof(*live), 4, fp);
	return strncmp(live, "live", 4);
}
