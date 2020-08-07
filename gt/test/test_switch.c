#include <stdio.h>
#include <stdlib.h>

void guess_error(){
	printf("sorry, guess erro!\n");
	exit(-1);
}

int main(){
	int input;
	printf("Please intput the choice: ");
	scanf("%d", &input);

	switch(input){
		case 0:
			printf("Hello, your choice is 0!\n");
			break;
		case 2:
			printf("Hello, your choice is 2!\n");
			break;
		case 5:
			printf("Hello, your choice is 5!\n");
			break;
		case 6:
			printf("Hello, your choice is 6!\n");
			break;
		case 8:
			printf("Hello, your choice is 8!\n");
			break;
		case 9:
			printf("Hello, your choice is 9!\n");
			break;
		case 11:
			printf("Hello, your choice is 11!\n");
			break;
		case 12:
			printf("Hello, your choice is 12!\n");
			break;
		case 13:
			printf("Hello, your choice is 13!\n");
			break;
		default:
			guess_error();
			break;

	}
}
