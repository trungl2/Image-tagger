#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <ctype.h>
#include <math.h>

#include "sha256.h"

#define NUM_CHAR4_HASHES 10
#define NUM_CHAR6_HASHES 20
#define BYTES_IN_HASH 32
#define MAX_WORD_LEN 30
#define MAX_COMMON_PWDS 80000
#define NUM_ALPHANUMERIC 36 //maybe 35 because a-z = 0-25
#define CHAR_SPAN 94
#define NUM_HASHED_PWDS 30
#define ASCII_UPPER_TO_LOWER 6

//converts word to byte format --> method type and return type might be wrong
void convert_to_hash(BYTE *word, BYTE *buffer) { //maybe return BYTE
	SHA256_CTX ctx;
	
	sha256_init(&ctx);
	sha256_update(&ctx, word, 4); //NEED TO ADJUST FOR SECOND PART
	sha256_final(&ctx, buffer);
	
}


//checks if the guess was in the array of words GET RID OF 4's LATER
int check_guess(char *guess, BYTE **hashes_arr) {
	BYTE hashed_guess[SHA256_BLOCK_SIZE];
	BYTE *guess_byte = (BYTE*)guess;
	convert_to_hash(guess_byte, hashed_guess);
	
	//printf("%s ", guess);
	for(int j=0; j<10; j++) {
		if (!memcmp(hashed_guess, hashes_arr[j], SHA256_BLOCK_SIZE)) { //memcmp returns 0 if they are the same
			printf("\n%d: %s\n", j, guess);
			return 1;
		}
	}
	return 0;
}

//does permutation of possible letters to numbers and checks if it the result
//is in the list of hashes
// MAKE A MODE SUCH THAT FOR WHEN STR IS A MIX OF CAPS AND NON-CAPS, ONLY NONCAPS ON TURNED INTO NUMBERS
void letter_to_num_permutation(char *str, int start_point, int end_point, BYTE **hashes_arr, int check_upper) {
	char new_str[strlen(str) + 1];
	check_guess(str, hashes_arr);
	
	int has_changed = 0;
	
	for(int i=start_point; i<end_point; i++) {
		if(str[i] == 'e' || (str[i] == 'E' && check_upper)) {
			strcpy(new_str, str);
			new_str[i] = '3';
			has_changed = 1;
		} else if(str[i] == 'o' || (str[i] == 'O' && check_upper)) {
			strcpy(new_str, str);
			new_str[i] = '0';
			has_changed = 1;
		} else if(str[i] == 'r' || (str[i] == 'R' && check_upper)) {
			strcpy(new_str, str);
			new_str[i] = '2';
			has_changed = 1;
		} else if(str[i] == 'a' || (str[i] == 'A' && check_upper)) {
			strcpy(new_str, str);
			new_str[i] = '4';
			has_changed = 1;
		} else if(str[i] == 'l' || (str[i] == 'L' && check_upper)) {
			strcpy(new_str, str);
			new_str[i] = '1';
			has_changed = 1;
		} else if(str[i] == 's' || (str[i] == 'S'&& check_upper)) {
			strcpy(new_str, str);
			new_str[i] = '$';
			has_changed = 1;
		}
		
		if(has_changed) {
			letter_to_num_permutation( new_str,i+1, end_point, hashes_arr, check_upper);
		}
	}
}


void compare_pass_to_hash(char *pwd_file, char *hash_file) {
	int i;
	
	//process list of password file
    //finds number of passwords in the text file
    FILE *fileptr = fopen(pwd_file, "r");
    char word[MAX_WORD_LEN];
    int n = 0;
    while(fgets(word, MAX_WORD_LEN, fileptr)!=NULL){
    	n++;
    }

    // store all of the passwords and removes new line character
    char pwd_list[n][MAX_WORD_LEN];
    rewind(fileptr);
    for(i=0;i<n;i++){
        fgets(word, MAX_WORD_LEN, fileptr);
        word[strlen(word)-1] = '\0';
        strncpy(pwd_list[i], word, strlen(word) + 1);
        
    }
	fclose(fileptr);
	
	//process hash file
	char *buffer;
	long file_len;
	fileptr = fopen(hash_file, "rb"); // Open the file for reading in binary
	fseek(fileptr, 0, SEEK_END); //finds start point (0) and end point (end) and places the ptr at the end point
	file_len = ftell(fileptr); //use the ptr to get the len
	rewind(fileptr); //puts the pts back to the start
	
	//stores hashes in the buffer
	buffer = malloc((file_len) * sizeof(char));
	fread(buffer, file_len, 1, fileptr);               //third input --> specifies size what we are reading in term of size_t
	

	
	fclose(fileptr);
	//printf("%ld", file_len);
	
	//initialise array to store encoded hexadecimal words
	int num_hash = file_len/BYTES_IN_HASH; // need to check on this
	BYTE **hashed_passes = malloc(num_hash * sizeof(*hashed_passes));
	for(i=0; i<num_hash; i++) {
		hashed_passes[i] = malloc(BYTES_IN_HASH * sizeof(BYTE)); //maybe leave at 4
	}
	

	//put the encoded hexadecimals into the array seperated by words
	int word_count = 0;
	int index = 0;
	for(i=0; i<file_len; i++) {
		hashed_passes[word_count][index] = buffer[i];
		//printf("%x ",words4[word_count][index]);
		index += 1;
		
		//reset bytes counted after every 32 bytes (after every word)
		if (index == BYTES_IN_HASH) {
			index = 0;
			word_count += 1;
		}
	}
	
	printf("%x\n%s\n\n\n", hashed_passes[0][0], pwd_list[0]);
	
	for(i=0; i<n; i++) {
		check_guess(pwd_list[i], hashed_passes);
	}
	
	
}






void guess_with_file(char *search_file, BYTE **hashes) {
    //finds number of words in the search file
    int i;
    FILE *fileptr = fopen(search_file, "r");
    char word[MAX_WORD_LEN];
    int num_words = 0;
    while(fgets(word, MAX_WORD_LEN, fileptr)!=NULL){
    	num_words++;
    }

    // store all of the searched words and removes new line character
    char searched_words[num_words][MAX_WORD_LEN];
    rewind(fileptr);
    for(i=0;i<num_words;i++){
        fgets(word, MAX_WORD_LEN, fileptr);
        word[strlen(word)-1] = '\0';
        strncpy(searched_words[i], word, strlen(word) + 1);
        
    }

	fclose(fileptr);

	//strategy 1: use all 4 character words to guess
	char char4_guess_template[] = "    ";
	char *char4_guess = &char4_guess_template[0];
	for(i=0; i<num_words; i++) {
		if (strlen(searched_words[i]) == 4) {
			
			//guess using the password from the searched file
			char4_guess[0] = searched_words[i][0];
			char4_guess[1] = searched_words[i][1];
			char4_guess[2] = searched_words[i][2];
			char4_guess[3] = searched_words[i][3];
			letter_to_num_permutation(char4_guess, 0, strlen(char4_guess), hashes, 1);
			
			//try variations of the word 
			//case 1: first character to upper
			if(isalpha(searched_words[i][0]) && (char4_guess[0] != toupper(searched_words[i][0]))) {
				char4_guess[0] = toupper(searched_words[i][0]);
				letter_to_num_permutation(char4_guess, 0, strlen(char4_guess), hashes, 1);
			}

			//case 2: all characters to upper
			for(int k=0; k<4; k++) {
				if(isalpha(searched_words[i][k])) {
					char4_guess[k] = toupper(searched_words[i][k]);
				}
			}
			letter_to_num_permutation(char4_guess, 0, strlen(char4_guess), hashes, 1);
		}
	}
}

void brute_force_lowercase_alpha(BYTE **hashes) {
	//strategy 1: use all 4 character words to guess
	char char4_guess_template[] = "    ";
	char *char4_guess = &char4_guess_template[0];
	for(int i=0; i<26; i++) {
		for(int j=0; j<26; j++) {
			for(int k=0; k<26; k++) {
				for(int p=0; p<26; p++) {
					//guess using the password from the searched file
					//printf("///");
					
					
					char4_guess[0] = 'a' + i;
					char4_guess[1] = 'a' + j;
					char4_guess[2] = 'a' + k;
					char4_guess[3] = 'a' + p;
					
					letter_to_num_permutation(char4_guess, 0, strlen(char4_guess), hashes, 1);
					
					//try variations of the word 
					//case 1: first character to upper
					char4_guess[0] = toupper(char4_guess[0]);
					//printf("%s ", char4_guess);
					letter_to_num_permutation(char4_guess, 0, strlen(char4_guess), hashes, 1);
			
					//case 2: all characters to upper
					for (int m=1; m<4; m++) {
						char4_guess[m] = toupper(char4_guess[m]);
					}
					letter_to_num_permutation(char4_guess, 0, strlen(char4_guess), hashes, 1);
					
					//case 3: permutation of characters to uppercase WOULD NEED A ISALPHA CHECK HERE IN OTHER CASES
					//change all characters back to lowercase
					for (int m=0; m<4; m++) {
						char4_guess[m] = tolower(char4_guess[m]);
					}
					
				}
			}
		}
	}
}


void brute_force_mix_alpha(BYTE **hashes) {
	//strategy 1: use all 4 character words to guess
	char char4_guess_template[] = "    ";
	char *char4_guess = &char4_guess_template[0];
	for(int i=0; i<52; i++) {
		for(int j=0; j<52; j++) {
			for(int k=0; k<52; k++) {
				for(int p=0; p<52; p++) {
					//guess using the password from the searched file
					//printf("///");
					
					//skip over parts that are all lower case, we've already looked through that
					if(i>=26 && j>=26 && k>=26 && p>=26) {
						continue;
					}
					
					if(i<26) {
						char4_guess[0] = 'A' + i;
					} else {
						char4_guess[0] = 'A' + i + ASCII_UPPER_TO_LOWER;
					}
					
					if(j<26) {
						char4_guess[1] = 'A' + j;
					} else {
						char4_guess[1] = 'A' + j + ASCII_UPPER_TO_LOWER;
					}
					if(k<26) {
						char4_guess[2] = 'A' + k;
					} else {
						char4_guess[2] = 'A' + k + ASCII_UPPER_TO_LOWER;
					}
					
					if(p<26) {
						char4_guess[3] = 'A' + p;
					} else {
						char4_guess[3] = 'A' + p + ASCII_UPPER_TO_LOWER;
					}
					
					//printf("%s ", char4_guess);
					
					letter_to_num_permutation(char4_guess, 0, strlen(char4_guess), hashes, 0);
				}
			}
		}
	}
}

int main(int argc, char* argv[]) {
	
	//action when there are 2 arguments
	if(argc == 3) {
		compare_pass_to_hash(argv[1], argv[2]);
		return 0;
	}
	
	int i;
	FILE *fileptr;
	char *buffer;
	long file_len;
	 
	//processes the 4 character hash file
	fileptr = fopen("pwd4sha256", "rb"); 	// Open the file for reading in binary
	fseek(fileptr, 0, SEEK_END); 			//finds start point (0) and end point (end) and places the ptr at the end point
	file_len = ftell(fileptr); 				//use the ptr to get the len
	rewind(fileptr); 						//puts the pts back to the start
	
	//stores hashes in the buffer
	buffer = malloc((file_len) * sizeof(char));
	fread(buffer, file_len, 1, fileptr);
	
	fclose(fileptr);
	printf("%ld", file_len);
	
	//initialise array to store encoded hexadecimal words
	BYTE **char4_hashes = malloc(NUM_CHAR4_HASHES * sizeof(*char4_hashes));
	for(i=0; i<NUM_CHAR4_HASHES; i++) {
		char4_hashes[i] = malloc(BYTES_IN_HASH * sizeof(BYTE));
	}
	
	//put the encoded hexadecimals into the array seperated by words
	int word_count = 0;
	int index = 0;
	for(i=0; i<file_len; i++) {
		char4_hashes[word_count][index] = buffer[i];
		//printf("%x ",words4[word_count][index]);
		index += 1;
		
		//reset bytes counted after every 32 bytes (after every word)
		if (index == BYTES_IN_HASH) {
			index = 0;
			word_count += 1;
		}
		
	}
	
	/*
	char **found_words = malloc((NUM_CHAR4_HASHES + NUM_CHAR6_HASHES) * sizeof(*founds_words));
	for(int i=0; i<NUM_CHAR4_HASHES; i++) {
		*found_words = malloc((4+1) * sizeof(char));
	}
	for(int i=10; i<10 + NUM_CHAR6_HASHES; i++) {
		*found_words = malloc((6+1) * sizeof(char));
	}
	*/
	
	printf("\n//////////////////////////////\n");
    //guess_with_file("common_passwords.txt", char4_hashes);
    //guess_with_file("dict4words.txt",char4_hashes); 
    //brute_force_lowercase_alpha(char4_hashes);
    brute_force_mix_alpha(char4_hashes);
    
    
    
    
    
    
    
    
	//free
	//dont free this because already freed in buffer?
	/*
	for (i=0; i<NUM_WORDS4; i++) {
		free(words4[i]);
	}
	free(words4);
	*/
	free(buffer);

	
	return 0;
}


	

	//strategy 2: use 4 character dictionary to guess
	
	
	
	

