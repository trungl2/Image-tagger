#include <stdio.h>
#include <stdlib.h>
#include <string.h>  
#include <memory.h>

#include "sha256.h"

#define NUM_WORDS4 10
#define WORD_BYTES 32
#define MAX_WORD_LEN 30
#define MAX_COMMON_PWDS 80000
#define NUM_ALPHANUMERIC 36 //maybe 35 because a-z = 0-25
#define CHAR_SPAN 94

//converts word to byte format --> method type and return type might be wrong
void convert_to_byte(BYTE *word, BYTE *buffer) { //maybe return BYTE
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
	int j;
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
	

	
	printf("\n//////////////////////////////\n");

	
	/*//prints
	for(i=0; i<NUM_WORDS4; i++) {
		for(j=0; j<WORD_BYTES; j++) {
			printf("%x ", words4[i][j]);
		}
		printf("\n");
	}*/
	
	
	printf("\nbrute force: \n");
	
	
	

	/*
	char arr[] = "   ";
	char* m = &arr[0];
	BYTE *text1;
	BYTE buf[SHA256_BLOCK_SIZE];
	BYTE hash1[SHA256_BLOCK_SIZE] = {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
								 0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
	for(int i=0; i<26; i++) {
		for(int j=0; j<26; j++) {
			for( int k=0; k<26; k++) {
				
				m[0] = 'a' + i;
				m[1] = 'a' + j;
				m[2] = 'a' + k;
				
				
				text1=m;
				
				convert_to_byte3(text1, buf); //make sure to change 4-->3 in this function when use
				

				
				if(compare_bytes(buf, hash1)) {
					printf("Yayw");
					printf("%s", m);
				
				}
			}
		}
	}
	*/
	
	
	char init[] = "    ";
	char* guess = &init[0];
	BYTE byte_guess[SHA256_BLOCK_SIZE];
	for(int i=0; i<94; i++) {
		for(int j=0; j<94; j++) {
			for( int k=0; k<94; k++) {
				for(int l=0; l<94; l++) {
					
					guess[0] = ' ' + i;
					guess[1] = ' ' + j;
					guess[2] = ' ' + k;
					guess[3] = ' ' + l;

					//printf("%s ", guess);
					BYTE *b_guess = guess;
					
					convert_to_byte(b_guess, byte_guess);
					
					for(int t=0; t<10; t++) {
						if (compare_bytes(byte_guess, words4[t])) {
							printf("%s\n", guess);
							//break
						}
					}
				}
			}
		}
	}
	
	

    /*
    // store all of the common passwords
    fileptr = fopen("common_passwords.txt", "r");
    char word[MAX_WORD_LEN];
    int n = 0;
    int num_common = 0;
    while(fgets(word, MAX_WORD_LEN, fileptr)!=NULL){
    	num_common++;
    	if(strlen(word) == 5) {
    		n++;
    	}
    }
    
    char common_pwds[n][MAX_WORD_LEN];
    rewind(fileptr);
    for(i=0;i<num_common;i++){
        fgets(word, MAX_WORD_LEN, fileptr);
        printf("%d\n",strlen(word));
        if(strlen(word) == 5) {
        	
        	printf("%s\n", word);
        	strcpy(common_pwds[i], word);
        }
        
    }*/
    
    /* DELETE THIS 
    //finds number of common passwords in the text file
    fileptr = fopen("common_passwords.txt", "r");
    char word[MAX_WORD_LEN];
    int n = 0;
    while(fgets(word, MAX_WORD_LEN, fileptr)!=NULL){
    	n++;
    }

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
	

	
	//flags which characters were tried at a specified location 
	int tried_4chars[3][CHAR_SPAN]; //3 because dont need to worry about newline char and null byte
	
	DELETE THIS*/
	
	//init_4char[] = "    ";
	//char* guess_4char = &init_4char[0];
	
	/*
	//gets all the 4 character common passwords uses them to guess
	printf("//////////////////////////////\n");
	char common_pwd[] = "    ";
	char *guess_4char = &common_pwd[0];
	BYTE byte_guess[SHA256_BLOCK_SIZE];
	for(i=0; i<n; i++) {
		if (strlen(common_pwds[i]) == 4) {
			
			guess_4char[0] = 't';
			guess_4char[1] = 'r';
			guess_4char[2] = 'u';
			guess_4char[3] = 'n';
			guess_4char[4] = '\0';
			//printf("%d %s\n",i ,guess_4char);
			
			convert_to_byte(guess_4char, byte_guess);

			
			for(j=0; j<10; j++) {
				if (compare_bytes(byte_guess, words4[j])) {
					printf("%d", j);
					printf("YAYYYYYYYYYYYYYYYYYYY");
					printf("%s\n", guess_4char);
				}
			}
		}
		
	}
	*/
	
	
	
	/*
	printf("%d", tried_4chars[0][0]);
	printf("%d", tried_4chars[1][0]);
	printf("%d", tried_4chars[0][1]);
	tried_4chars[1][0] = 1;
	printf("%d", tried_4chars[1][0]);
	
	memset(tried_4chars, 0, sizeof(tried_4chars));
	printf("%d", tried_4chars[1][0]);
	*/

	
	

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	//free
	for (i=0; i<NUM_WORDS4; i++) {
		free(words4[i]);
	}
	free(words4);
	free(buffer);
	
	
	
	
	
		
	

	
	
	return 0;
}











	/*
	BYTE a=0x82;
	
	for(int i=0; i<file_len; i++) {
		//printf("%x ", (unsigned char) buffer[i]);
		if((BYTE)buffer[i] == a) {
			printf("yay");
		}
		
	}
	*/


/*
	int i;
	
	FILE *fileptr;
	char *buffer;
	long file_len;
	
	fileptr = fopen("pwd4sha256", "rb"); // Open the file for reading in binary
	fseek(fileptr, 0, SEEK_END); //finds start point (0) and end point (end) and places the ptr at the end point
	file_len = ftell(fileptr); //use the ptr to get the len
	rewind(fileptr); //puts the pts back to the start
	
	//char *c;
	//for(i=0; i<file_len: i++) {
	//	printf("%c", fileptr);
	//	fileptr++;
	//}
	
	buffer = malloc((file_len+1) * sizeof(char));
	
	//third input --> specifies size what we are reading in term of size_t
	//eg if we reading an array of doubles, then since double = 8 in size_t
	//(or by using size_of),
	fread(buffer, file_len, 1, fileptr);
	fclose(fileptr);
	printf("\n%d\n", file_len);
	
	for(i=0; i<strlen(buffer); i++) {
		printf("%c", buffer[i]);
		if(i % 32 ==0) {
			printf("\n");
		}
	}
*/
