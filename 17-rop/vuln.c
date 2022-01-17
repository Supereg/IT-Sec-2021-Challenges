#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__asm__ (
	"maybe_useful:\n"
	"pop %rax\n"
	"ret\n"
	"maybe_also_useful:\n"
	"pop %rdx\n"
	"ret\n"
	"maybe_extremely_useful:\n"
	"syscall\n"
	"ret\n"
	"maybe_not_so_useful:\n"
	"nop\n"
	"nop\n"
	"nop\n"
	"nop\n"
	"ret\n"
);

const char* cool_string = "/bin/sh";

#define MAX_INPUT_LEN 20

int main(void)
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	char* line = NULL;
	size_t n = 0;
	puts("How long is your name?");
	getline(&line, &n, stdin);

	if (atoi(line) > MAX_INPUT_LEN) {
		puts("Sorry, no overflows here.");
		return -1;
	}

	unsigned char len = atoi(line);

	char input_buf[MAX_INPUT_LEN];
	printf("Enter ur name of length %hu:\n", len);
	int ret = read(STDIN_FILENO, input_buf, len);
	if (ret == -1) {
		puts("Could not read your input :-(");
		return -1;
	}
	printf("Your name is %d characters long!\n", ret);

	if (len > MAX_INPUT_LEN) {
		puts("Now ROP me!");
	}
	return 0;
}
