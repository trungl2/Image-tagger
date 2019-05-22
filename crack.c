#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <ctype.h>

#include "sha256.h"

#define NUM_WORDS4 10
#define WORD_BYTES 32
#define MAX_WORD_LEN 30
#define MAX_COMMON_PWDS 80000
#define NUM_ALPHANUMERIC 36 //maybe 35 because a-z = 0-25
#define CHAR_SPAN 94

//converts word to byte format --> method type and return type might be wrong
void convert_to_hash(BYTE *word, BYTE *buffer) { //maybe return BYTE
	//BYTE text1[] = {"abc"};
	//BYTE buffer[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	
	sha256_init(&ctx);
	sha256_update(&ctx, word, 4); //NEED TO ADJUST FOR SECOND PART
	sha256_final(&ctx, buffer);
	
	 
	 //const unsigned char *p1 = buf[0];
	 //printf("%u", p1);
	 
	 //return *buffer;
	 
}


//not same as word from above, more like encoded word
int compare_bytes(BYTE *word1, BYTE *word2) {
	//printf("\nword 1: %x" ,(unsigned char)word1[1]);
	//printf("    word 2: %x" ,(unsigned char)word2[1]);
	return !memcmp(word1, word2, SHA256_BLOCK_SIZE); //returns 0 if they are the same
}

//checks if the guess was in the array of words GET RID OF 4's LATER
int check_guess(char *guess, BYTE **words4) {
	BYTE hashed_guess[SHA256_BLOCK_SIZE];
	BYTE *guess_4char_byte = (BYTE*)guess;
	convert_to_hash(guess_4char_byte, hashed_guess);
	
	for(int j=0; j<10; j++) {
		if (compare_bytes(hashed_guess, words4[j])) {
			printf("%s\n", guess);
			return 1;
		}
	}
	return 0;
}

void letter_to_num_permutation(char *str, int start_point, int end_point, BYTE **words4) {
	char new_str[strlen(str) + 1];
	check_guess(str, words4);
	
	int has_changed = 0;
	
	for(int i=start_point; i<end_point; i++) {
		if(str[i] == 'e' || str[i] == 'E') {
			strcpy(new_str, str);
			new_str[i] = '3';
			has_changed = 1;
		} else if(str[i] == 'o' || str[i] == 'O') {
			strcpy(new_str, str);
			new_str[i] = '0';
			has_changed = 1;
		} else if(str[i] == 'r' || str[i] == 'R') {
			strcpy(new_str, str);
			new_str[i] = '2';
			has_changed = 1;
		} else if(str[i] == 'a' || str[i] == 'A') {
			strcpy(new_str, str);
			new_str[i] = '4';
			has_changed = 1;
		} else if(str[i] == 'l' || str[i] == 'L') {
			strcpy(new_str, str);
			new_str[i] = '1';
			has_changed = 1;
		}
		
		if(has_changed) {
			letter_to_num_permutation( new_str,i+1, end_point, words4);
		}
	}
}

int main(int argc, char* argv[]) {
	int i;
	FILE *fileptr;
	char *buffer;
	long file_len;
	 
	fileptr = fopen("pwd4sha256", "rb"); // Open the file for reading in binary
	fseek(fileptr, 0, SEEK_END); //finds start point (0) and end point (end) and places the ptr at the end point
	file_len = ftell(fileptr); //use the ptr to get the len
	rewind(fileptr); //puts the pts back to the start
	
	buffer = malloc((file_len) * sizeof(char));

	 
	//third input --> specifies size what we are reading in term of size_t
	//eg if we reading an array of doubles, then since double = 8 in size_t
	//(or by using size_of),
	fread(buffer, file_len, 1, fileptr);
	

	
	fclose(fileptr);
	printf("%ld", file_len);
	
	//initialise array to store encoded hexadecimal words
	BYTE **words4 = malloc(NUM_WORDS4 * sizeof(*words4));
	for(i=0; i<NUM_WORDS4; i++) {
		words4[i] = malloc(4 * sizeof(BYTE)); //maybe not +1 since dont need null byte in array of chars
	}
	

	//put encoded hexadecimal words into the array
	int word_count = 0;
	int index = 0;

	for(i=0; i<file_len; i++) {
		words4[word_count][index] = buffer[i];
		
		//printf("%x ",words4[word_count][index]);
		index += 1;
		
		//reset bytes counted after every 32 bytes or after every word
		if (index == WORD_BYTES) {
			index = 0;
			word_count += 1;
		}
		
	}
	

	
	printf("\n//////////////////////////////yay\n");
	
	printf("yay");

    
    //finds number of common passwords in the text file
    fileptr = fopen("common_passwords.txt", "r");
    char word[MAX_WORD_LEN];
    int n = 0;
    while(fgets(word, MAX_WORD_LEN, fileptr)!=NULL){
    	n++;
    }
    
    printf("yay");

    // store all of the common passwords and removes new line character
    char common_pwds[n][MAX_WORD_LEN];
    rewind(fileptr);
    for(i=0;i<n;i++){
        fgets(word, MAX_WORD_LEN, fileptr);
        word[strlen(word)-1] = '\0';
        strncpy(common_pwds[i], word, strlen(word) + 1);
        
    }
    
	printf("%s\n", common_pwds[n-2]);
	printf("%s\n", common_pwds[0]);
	fclose(fileptr);
	
	
	
	//init_4char[] = "    ";
	//char* guess_4char = &init_4char[0];
	
	
	//strategy 1: use all 4 character common passwords to guess
	printf("//////////////////////////////\n");
	char common_pwd[] = "    ";
	char *guess_4char = &common_pwd[0];
	for(i=0; i<n; i++) {
		if (strlen(common_pwds[i]) == 4) {
			
			//guess the password in the common passwords
			guess_4char[0] = common_pwds[i][0];
			guess_4char[1] = common_pwds[i][1];
			guess_4char[2] = common_pwds[i][2];
			guess_4char[3] = common_pwds[i][3];
			//check_guess(guess_4char, words4); --> this is now done in first iteration of letter_to_num_permutation
			letter_to_num_permutation(guess_4char, 0, strlen(guess_4char), words4);
			
			//try variations of the word (caps, changing words to numbers or numbers to words)
			//case 1: first character to upper
			if(isalpha(common_pwds[i][0])) {
				guess_4char[0] = toupper(common_pwds[i][0]);
			}
			//check_guess(guess_4char, words4);
			letter_to_num_permutation(guess_4char, 0, strlen(guess_4char), words4);

			
			//case 2: all characters to upper
			for(int k=0; k<4; k++) {
				if(isalpha(common_pwds[i][k])) {
					guess_4char[k] = toupper(common_pwds[i][k]);
				}
			}
			if(isalpha(common_pwds[i][0])) {
				guess_4char[0] = toupper(common_pwds[i][0]);
			}
			//check_guess(guess_4char, words4);
			letter_to_num_permutation(guess_4char, 0, strlen(guess_4char), words4);
		}
		
		
	}
	
	
	//free
	for (i=0; i<NUM_WORDS4; i++) {
		free(words4[i]);
	}
	free(words4);
	free(buffer);

	
	return 0;
}

