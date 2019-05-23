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

typedef enum {
	HASH_4CHARS,
	HASH_6CHARS
} HASH_MODE;
//converts word to byte format --> method type and return type might be wrong
void convert_to_hash(BYTE *word, BYTE *buffer) { //maybe return BYTE
	SHA256_CTX ctx;
	
	sha256_init(&ctx);
	sha256_update(&ctx, word, 4); //NEED TO ADJUST FOR SECOND PART
	sha256_final(&ctx, buffer);
	
}


//checks if the guess was in the array of words GET RID OF 4's LATER
int check_guess(char *guess, BYTE **hashes_arr, HASH_MODE hash_mode) {
	BYTE hashed_guess[SHA256_BLOCK_SIZE];
	BYTE *guess_byte = (BYTE*)guess;
	convert_to_hash(guess_byte, hashed_guess);
	
	int num_hashes;
	if(hash_mode == HASH_4CHARS) {
		num_hashes = NUM_CHAR4_HASHES;
	} else {
		num_hashes = NUM_CHAR6_HASHES;
	}
	
	//printf("%s ", guess);
	for(int j=0; j<num_hashes; j++) {
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
void letter_to_num_permutation(char *str, int start_point, int end_point, BYTE **hashes_arr, int check_upper, HASH_MODE hash_mode) {
	char new_str[strlen(str) + 1];
	check_guess(str, hashes_arr, hash_mode);
	
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
			letter_to_num_permutation( new_str,i+1, end_point, hashes_arr, check_upper, hash_mode);
		}
	}
}

/*
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
		check_guess(pwd_list[i], hashed_passes, );
	}
	
	//free
	for(i=0; i<num_hash; i++) {
		free(hashed_passes[i]);
	}
	free(hashed_passes);
	
}
*/






void guess_with_file(char *search_file, BYTE **hashes, HASH_MODE hash_mode) {
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
	
	//adjust length of string based on the hash that we have and number of hashes
	int answ_word_len;
	if (hash_mode == HASH_4CHARS) {
		answ_word_len = 4;
		
	} else {
		answ_word_len = 6;
	}

	//strategy 1: use all 4 character words to guess
	char guess_template4[] = "    ";
	char guess_template6[] = "      ";
	char *guess;
	if(hash_mode == HASH_4CHARS) {
		guess = &guess_template4[0];
	} else {
		guess = &guess_template6[0];
	}
	
	for(i=0; i<num_words; i++) {
		if (strlen(searched_words[i]) == answ_word_len) {
			
			//guess using the password from the searched file
			guess[0] = searched_words[i][0];
			guess[1] = searched_words[i][1];
			guess[2] = searched_words[i][2];
			guess[3] = searched_words[i][3];
			if(hash_mode == HASH_6CHARS) {
				guess[4] = searched_words[i][4];
				guess[5] = searched_words[i][5];
			}
			letter_to_num_permutation(guess, 0, strlen(guess), hashes, 1, hash_mode);
			
			//try variations of the word 
			//case 1: first character to upper
			if(isalpha(searched_words[i][0]) && (guess[0] != toupper(searched_words[i][0]))) {
				guess[0] = toupper(searched_words[i][0]);
				letter_to_num_permutation(guess, 0, strlen(guess), hashes, 1, hash_mode);
			}

			//case 2: all characters to upper
			for(int k=0; k<answ_word_len; k++) {
				if(isalpha(searched_words[i][k])) {
					guess[k] = toupper(searched_words[i][k]);
				}
			}
			letter_to_num_permutation(guess, 0, strlen(guess), hashes, 1, hash_mode);
		}
	}
}

/*
void brute_force_lowercase_alpha(BYTE **hashes, HASH_MODE hash_mode) {
	
	//adjust length of string based on the hash that we have and number of hashes
	char guess_template4[] = "    ";
	char guess_template6[] = "      ";
	char *guess;
	int char6_loop;
	if(hash_mode == HASH_4CHARS) {
		guess = &guess_template4[0];
		char6_loop = 0;
	} else {
		guess = &guess_template6[0];
		char6_loop = 25;
	}
	for(int i=0; i<26; i++) {
		for(int j=0; j<26; j++) {
			for(int k=0; k<26; k++) {
				for(int p=0; p<26; p++) {
					for(int a=char6_loop; a<26; a++) {
						for(int b=char6_loop; b<26; b++) {
							//guess using the password from the searched file
							//printf("///");
							guess[0] = 'a' + i;
							guess[1] = 'a' + j;
							guess[2] = 'a' + k;
							guess[3] = 'a' + p;
							if(hash_mode == HASH_6CHARS) {
								guess[4] = 'a' + a;
								guess[5] = 'a' + b;
							}
		
							
							letter_to_num_permutation(guess, 0, strlen(guess), hashes, 1, hash_mode);
							
							//try variations of the word 
							//case 1: first character to upper
							guess[0] = toupper(guess[0]);
							//printf("%s ", char4_guess);
							letter_to_num_permutation(guess, 0, strlen(guess), hashes, 1, hash_mode);
					
							//case 2: all characters to upper
							for (int m=1; m<4; m++) {
								guess[m] = toupper(guess[m]);
							}
							letter_to_num_permutation(guess, 0, strlen(guess), hashes, 1, hash_mode);
						}
					}
				}
			}
		}
	}
}


void brute_force_mix_alpha(BYTE **hashes, HASH_MODE hash_mode) {
	//strategy 1: use all 4 character words to guess
	
	//adjust length of string based on the hash that we have and number of hashes
	char guess_template4[] = "    ";
	char guess_template6[] = "      ";
	char *guess;
	int char6_loop;
	if(hash_mode == HASH_4CHARS) {
		guess = &guess_template4[0];
		char6_loop = 0;
	} else {
		guess = &guess_template6[0];
		char6_loop = 51;
	}
	for(int i=0; i<52; i++) {
		for(int j=0; j<52; j++) {
			for(int k=0; k<52; k++) {
				for(int p=0; p<52; p++) {
					for(int a=char6_loop; a<26; a++) {
						for(int b=char6_loop; b<26; b++) {
							//guess using the password from the searched file
							//printf("///");
							
							//skip over parts that are all lower case, we've already looked through that
							if(i>=26 && j>=26 && k>=26 && p>=26) {
								continue;
							}
							
							if(i<26) {
								guess[0] = 'A' + i;
							} else {
								guess[0] = 'A' + i + ASCII_UPPER_TO_LOWER;
							}
							
							if(j<26) {
								guess[1] = 'A' + j;
							} else {
								guess[1] = 'A' + j + ASCII_UPPER_TO_LOWER;
							}
							if(k<26) {
								guess[2] = 'A' + k;
							} else {
								guess[2] = 'A' + k + ASCII_UPPER_TO_LOWER;
							}
							
							if(p<26) {
								guess[3] = 'A' + p;
							} else {
								guess[3] = 'A' + p + ASCII_UPPER_TO_LOWER;
							}
							 
							if(hash_mode == HASH_6CHARS) {
								if(a<26) {
									guess[4] = 'A' + a;
								} else {
									guess[4] = 'A' + a + ASCII_UPPER_TO_LOWER;
								}
								
								if(b<26) {
									guess[5] = 'A' + b;
								} else {
									guess[5] = 'A' + b + ASCII_UPPER_TO_LOWER;
								}
							}
		
							
							//printf("%s ", char4_guess);
							
							letter_to_num_permutation(guess, 0, strlen(guess), hashes, 0, hash_mode);
						}
					}
				}
			}
		}
	}
}
*/

BYTE **read_hash_file(char *hash_file, int num_hashes) {
	int i;
	FILE *fileptr;
	char *buffer;
	long file_len;
	 
	//processes the 4 character hash file
	fileptr = fopen(hash_file, "rb"); 	// Open the file for reading in binary
	fseek(fileptr, 0, SEEK_END); 			//finds start point (0) and end point (end) and places the ptr at the end point
	file_len = ftell(fileptr); 				//use the ptr to get the len
	rewind(fileptr); 						//puts the pts back to the start
	
	//stores hashes in the buffer
	buffer = malloc((file_len) * sizeof(char));
	fread(buffer, file_len, 1, fileptr);
	
	printf("%ld\n", file_len);
	fclose(fileptr);
	
	//initialise array to store encoded hexadecimal words
	BYTE **hashes = malloc(num_hashes * sizeof(*hashes));
	for(i=0; i<num_hashes; i++) {
		hashes[i] = malloc(BYTES_IN_HASH * sizeof(BYTE));
	}
	printf("yay");
	
	//put the encoded hexadecimals into the array seperated by words
	int word_count = 0;
	int index = 0;
	for(i=0; i<file_len; i++) {
		hashes[word_count][index] = buffer[i];
		//printf("%x ",words4[word_count][index]);
		index += 1;
		
		//reset bytes counted after every 32 bytes (after every word)
		if (index == BYTES_IN_HASH) {
			index = 0;
			word_count += 1;
		}
		
	}
	printf("yay");
	
	//free
	//dont free this because already freed in buffer?
	/*
	for (i=0; i<NUM_WORDS4; i++) {
		free(words4[i]);
	}
	free(words4);
	*/
	free(buffer);
	printf("yay");
	
	return hashes;
}

int main(int argc, char* argv[]) {
	
	/*
	//action when there are 2 arguments
	if(argc == 3) {
		compare_pass_to_hash(argv[1], argv[2]);
		return 0;
	}
	*/
	BYTE **char4_hashes = read_hash_file("pwd4sha256", NUM_CHAR4_HASHES);
	BYTE **char6_hashes = read_hash_file("pwd6sha256", NUM_CHAR6_HASHES);
	
	/*
	char **found_words = malloc((NUM_CHAR4_HASHES + NUM_CHAR6_HASHES) * sizeof(*founds_words));
	for(int i=0; i<NUM_CHAR4_HASHES; i++) {
		*found_words = malloc((4+1) * sizeof(char));
	}
	for(int i=10; i<10 + NUM_CHAR6_HASHES; i++) {
		*found_words = malloc((6+1) * sizeof(char));
	}
	*/
	
	HASH_MODE hash_mode = HASH_4CHARS;
	
	printf("\n//////////////////////////////\n");
    guess_with_file("common_passwords.txt", char4_hashes, hash_mode);
    //guess_with_file("dict4words.txt",char4_hashes, hash_mode); 
    //brute_force_lowercase_alpha(char4_hashes, hash_mode);
    //brute_force_mix_alpha(char4_hashes, hash_mode);
    
    //HASH_MODE hash_mode = HASH_6CHARS;
    

	return 0;
}

	
	
	

