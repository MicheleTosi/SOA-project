#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <termios.h>

#include "user.h"

#define LINE_SIZE 100

#define DEVICE_PATH "/dev/ref_monitor"
#define FS_PATH "/home/vboxuser/Scrivania/SOA-project/singlefile-FS/mount/the-file"

struct termios orig_term_conf;

void show_ascii_art() {
    printf(CLEAR_SCREEN "###############################################################\n");
    printf("#"RED GRASSETTO "___       ___     __   ___  ___  ___  __   ___       __   ___"RESET"#\n");
    printf("#"RED GRASSETTO " |  |__| |__     |__) |__  |__  |__  |__) |__  |\\ | /  ` |__ "RESET"#\n");
    printf("#"RED GRASSETTO " |  |  | |___    |  \\ |___ |    |___ |  \\ |___ | \\| \\__, |___"RESET"#\n");
    printf("#"RED GRASSETTO "                                                             "RESET"#\n");
    printf("#"RED GRASSETTO "       __         ___  __   __                               "RESET"#\n");
    printf("#"RED GRASSETTO " |\\/| /  \\ |\\ | |  |  /  \\ |__)                              "RESET"#\n");
    printf("#"RED GRASSETTO " |  | \\__/ | \\| |  |  \\__/ |  \\                              "RESET"#\n");
    printf("###############################################################\n\n");
}

void show_helper(){
	printf("###############################################################\n");
    printf("# " GRASSETTO RED "Usage:" RESET " ref_monitor [COMMAND] [OPTIONS]                      #\n");
    printf("###############################################################\n");
    printf("#                                                             #\n");
    printf("# " GRASSETTO RED "Commands:" RESET "                                                   #\n");

    // Comandi in grassetto
    printf("#   " GRASSETTO "start" RESET "               Start the reference monitor           #\n");
    printf("#   " GRASSETTO "stop" RESET "                Stop the reference monitor            #\n");
    printf("#   " GRASSETTO "reconfig_on" RESET "         Start the reference monitor in        #\n");
    printf("#                       reconfig_mode                         #\n");
    printf("#   " GRASSETTO "reconfig_off" RESET "        Stop the reference monitor in         #\n");
    printf("#                       reconfig_mode                         #\n");
    printf("#   " GRASSETTO "status" RESET "              Show current status                   #\n");
    printf("#   " GRASSETTO "set-password" RESET "        Change the password for the monitor   #\n");
    printf("#   " GRASSETTO "add-path [path]" RESET "     Add a new protected path              #\n");
    printf("#   " GRASSETTO "remove-path [path]" RESET "  Remove a protected path               #\n");
    printf("#   " GRASSETTO "print-logs" RESET "          List events log                       #\n");
    printf("#   " GRASSETTO "exit" RESET "                Close program                         #\n");
    printf("#                                                             #\n");
    printf("# " GRASSETTO RED "Options:" RESET "                                                    #\n");
    printf("#   " GRASSETTO "--hide" RESET "              Hide password                         #\n");
    printf("#                                                             #\n");
    printf("# "GRASSETTO RED "Examples:" RESET "                                                   #\n");
    printf("#   ref_monitor start                                         #\n");
    printf("#   ref_monitor set-password                                  #\n");
    printf("#   ref_monitor add-path /home/user/secure_folder             #\n");
    printf("#   ref_monitor list-paths                                    #\n");
    printf("#                                                             #\n");

    // "Note" in rosso
    printf("# " GRASSETTO RED "Note:" RESET " Make sure to run the commands with appropriate        #\n");
    printf("#       privileges (e.g., sudo).                              #\n");
    printf("#                                                             #\n");
    printf("# " GRASSETTO RED "Note:" RESET " default password is \"password\"                        #\n");
    printf("###############################################################\n\n");
}

void print_logs(){
	char cmd[LINE_SIZE];
	if (access(FS_PATH, R_OK) != 0) {
    	fprintf(stderr, "Log is not mounted\n");
    	return;
    }
    printf("\n\n");
   	sprintf(cmd,"cat %s",FS_PATH);
   	system(cmd);
}

int main() {
	int fd;
	ssize_t wrt;
	char *command;
	char cmd[LINE_SIZE];
	char pass[LINE_SIZE];
	char new_pass[LINE_SIZE];
	char new_pass2[LINE_SIZE];
	char *ret;
	
    // Mostra l'ASCII art all'avvio
    show_ascii_art();
    show_helper();

    // Controlla se l'utente è root
    if (getuid() != 0) {
        printf("Errore: Devi essere root per eseguire questo programma.\n");
        return 1;
    }
    
    printf("Inserisci comando:\n> ");
    fgets(cmd, LINE_SIZE, stdin);
    
    //Rimuovo newline inserito da fgets
    cmd[strcspn(cmd, "\n")]=0;
    
    if(strstr(cmd, "print-logs")!=NULL){
    	print_logs();
    	return 0;
    }
    
    if(strstr(cmd, "exit")!=NULL){
    	printf("\nExiting..\n\n");
    	return 0;
    }
    
    if((ret=strstr(cmd, "--hide"))!=NULL){
    	*(--ret)='\0';
    	no_echo_input(&orig_term_conf);
    }
    
    printf("Inserisci password:\n> ");
    fgets(pass, LINE_SIZE, stdin);
    pass[strcspn(pass, "\n")]=0;
    
    if(ret!=NULL) printf("\n");
    
    if(strstr(cmd, "set-pass")!=NULL){
    	printf("Inserisci la nuova password:\n> ");
    	fgets(new_pass, LINE_SIZE, stdin);
    	new_pass[strcspn(new_pass, "\n")]=0;
    	if(ret!=NULL) printf("\n"); //se pass hide mando a capo prima di scrivere
    	
    	printf("Re-inserisci la nuova password:\n> ");
    	fgets(new_pass2, LINE_SIZE, stdin);
    	new_pass2[strcspn(new_pass2, "\n")]=0;
    	if(ret!=NULL) printf("\n");	//se passowrd hide mando a capo prima di scrivere
    	
    	if(strcmp(new_pass, new_pass2)){
	    	if(ret!=NULL) reset_echo_input(&orig_term_conf);
    		printf("Le pass inserite risultano essere diverse\n");
    		return 1;
    	}
    	
    	command=malloc(strlen(cmd)+strlen(pass)+strlen(new_pass)+10);
	 	if(!command){
	 		printf("malloc non riuscita\n");
	 	}
	 	sprintf(command, "%s -np \"%s\" -p \"%s\"", cmd, new_pass, pass);
    }else{
    	command=malloc(strlen(cmd)+strlen(pass)+10);
	 	if(!command){
	 		printf("malloc non riuscita\n");
	 	}
	 	sprintf(command, "%s -p \"%s\"", cmd, pass);
    }
    
    if(ret!=NULL) reset_echo_input(&orig_term_conf);
    
    
    
    fd=open(DEVICE_PATH, O_WRONLY);
    if(fd<0){
    	printf("Failed to open device\n");
    	return 1;
    }
    wrt=write(fd, command, strlen(command));
    free(command);
    if(wrt<0){
    	printf("Failed to write to device, %ld\n", wrt);
    	return 1;
    }

    return 0;
}
