#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct user {
	int user_id;
	char name[32];
	int birthday;
	int is_admin;
};

void win() {
	execl("/bin/flag", "/bin/flag", NULL);
}

int main() {
	setbuf(stdout, NULL);

	struct user new_user;
	memset(&new_user, 0, sizeof(new_user));

	printf("Please enter your name:");
	fgets(new_user.name, 200, stdin);
	strtok(new_user.name, "\n");
	printf("Hello %s!\n", new_user.name);

	if(new_user.is_admin == 1) {
		win();
	}
	return 0;
}
