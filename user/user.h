#define GRASSETTO "\033[1m"
#define RED "\033[31m"
#define RESET "\033[0m"
#define CLEAR_SCREEN "\033[H\033[2J"


void no_echo_input(struct termios *original){
	struct termios term_conf;

    //cambio impostazioni terminale in modo da non eseguire la echo dei caratteri trasmessi su stdin
    tcgetattr(STDIN_FILENO, original);
    term_conf = *original;
    term_conf.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &term_conf);
}


void reset_echo_input(struct termios *original){
    //reset impostazioni terminale in modo che venga eseguita la echo dei caratteri trasmessi su stdin
    tcsetattr(STDIN_FILENO, TCSANOW, original);
}
