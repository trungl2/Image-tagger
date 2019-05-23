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
#define NUM_ALPHA 26
#define NUM_UPPER_LOWER_ALPHA 52
#define NUM_HASHED_PWDS 30
#define ASCII_UPPER_TO_LOWER 6
#define NUM_DIGITS 10

typedef enum {
	HASH_4CHARS,
	HASH_6CHARS
} HASH_MODE;
//converts word to byte format
void convert_to_hash(BYTE *word, BYTE *buffer) {
	
	char *char_word = (char*)word;
	
	SHA256_CTX ctx;
	
	sha256_init(&ctx);
	sha256_update(&ctx, word, strlen(char_word));
	sha256_final(&ctx, buffer);
	
}


//checks if the guess was in the array of words
int check_guess(char *guess, BYTE **hashes_arr, char **found_words) {
	static int tot_num_guesses = 0;
	BYTE hashed_guess[SHA256_BLOCK_SIZE];
	BYTE *guess_byte = (BYTE*)guess;
	
	//checks if the word has already been found
	if(strlen(guess) == 4) {
		for(int i=0; i<NUM_CHAR4_HASHES; i++) {
			if(strcmp(found_words[i], guess) == 0) {
				return tot_num_guesses;
			}
		}
	} else {
		for(int i=NUM_CHAR4_HASHES; i<NUM_CHAR4_HASHES+NUM_CHAR6_HASHES; i++) {
			if(strcmp(found_words[i], guess) == 0) {
				return tot_num_guesses;
			}
		}
	}
	
	//adjust number of hashes compared and offset of the found words array
	int num_hashes;
	int offset;
	if(strlen(guess) == 4) {
		num_hashes = NUM_CHAR4_HASHES;
		offset = 0;
	} else {
		num_hashes = NUM_CHAR6_HASHES;
		offset = NUM_CHAR4_HASHES;
	}
	
	//converts the guess to byte, compares it to the hashes
	//and prints if there is match
	convert_to_hash(guess_byte, hashed_guess);
	for(int j=0; j<num_hashes; j++) {
		tot_num_guesses += 1;
		if (!memcmp(hashed_guess, hashes_arr[j], SHA256_BLOCK_SIZE)) {
			strcpy(found_words[offset+j], guess);
			printf("%s %d\n", guess, j+1);
			return tot_num_guesses;
		}
	}
	return tot_num_guesses;
}

//does permutation of possible letters to numbers and checks if it the result
//is in the list of hashes
void letter_to_sym_permutation(char *str, int start_point, int end_point, 
	BYTE **hashes_arr, int check_upper, HASH_MODE hash_mode, 
	char **found_words, int max_guesses) {
	char new_str[strlen(str) + 1];
	
	if((check_guess(str, hashes_arr, found_words) >= max_guesses) && (max_guesses >= 0)) {
		exit(EXIT_SUCCESS);
	}
	
	//list of possible substitution for characters
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
		
		//repeat but use the next character as the starting point
		if(has_changed) {
			letter_to_sym_permutation( new_str,i+1, end_point, hashes_arr, 
				check_upper, hash_mode, found_words , max_guesses);
		}
	}
}

void compare_pass_to_hash(char *pwd_file, char *hash_file) {
	int i;
	
	//process list of password file
    //finds number of passwords in the text file
    FILE *fileptr = fopen(pwd_file, "r");
    char word[MAX_WORD_LEN];
    int num_pwds = 0;
    while(fgets(word, MAX_WORD_LEN, fileptr)!=NULL){
    	num_pwds++;
    }

    // store all of the passwords and removes new line character
    char pwd_list[num_pwds][MAX_WORD_LEN];
    rewind(fileptr);
    for(i=0;i<num_pwds;i++){
        fgets(word, MAX_WORD_LEN, fileptr);
        word[strlen(word)-1] = '\0';
        strncpy(pwd_list[i], word, strlen(word) + 1);
        
    }
	fclose(fileptr);
	
	//process hash file
	char *buffer;
	long file_len;
	fileptr = fopen(hash_file, "rb");
	fseek(fileptr, 0, SEEK_END);
	file_len = ftell(fileptr);
	rewind(fileptr);
	
	//stores hashes in the buffer
	buffer = malloc((file_len) * sizeof(char));
	fread(buffer, file_len, 1, fileptr);

	fclose(fileptr);
	
	//initialise array to store encoded hexadecimal words
	int num_hashes = file_len/BYTES_IN_HASH;
	BYTE **hashed_passes = malloc(num_hashes * sizeof(*hashed_passes));
	for(i=0; i<num_hashes; i++) {
		hashed_passes[i] = malloc(BYTES_IN_HASH * sizeof(BYTE));
	}
	

	//put the encoded hexadecimals into the array seperated by words
	int word_count = 0;
	int index = 0;
	for(i=0; i<file_len; i++) {
		hashed_passes[word_count][index] = buffer[i];
		index += 1;
		
		//reset bytes counted after every 32 bytes (after every word)
		if (index == BYTES_IN_HASH) {
			index = 0;
			word_count += 1;
		}
	}

	//convert the password to hashed form and compares it to the 
	//hashed passwords
	BYTE hashed_guess[SHA256_BLOCK_SIZE];
	BYTE *guess_byte;
	for(int i=0; i<num_pwds; i++) {
		guess_byte = (BYTE*)pwd_list[i];
		convert_to_hash(guess_byte, hashed_guess);
		for(int j=0; j<num_hashes; j++) {
			if (!memcmp(hashed_guess, hashed_passes[j], SHA256_BLOCK_SIZE)) {
				printf("%s %d\n", pwd_list[i], j+1);
			}
		}
	}
	free(buffer);
	
}

//makes a guess to the guess using a file and variations of the guess
void guess_with_file(char *search_file, BYTE **hashes, HASH_MODE hash_mode, 
	char **found_words, int max_guesses) {

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
	
	//adjust length of string based on what we are hashing
	int answ_word_len;
	if (hash_mode == HASH_4CHARS) {
		answ_word_len = 4;
	} else {
		answ_word_len = 6;
	}

	//adjust size of the template for the string depending on the hash mode
	char guess_template4[] = "    ";
	char guess_template6[] = "      ";
	char *guess;
	if(hash_mode == HASH_4CHARS) {
		guess = &guess_template4[0];
	} else {
		guess = &guess_template6[0];
	}
	
	//guess using the passwords from the searched file
	for(i=0; i<num_words; i++) {
		if (strlen(searched_words[i]) == answ_word_len) {
			guess[0] = searched_words[i][0];
			guess[1] = searched_words[i][1];
			guess[2] = searched_words[i][2];
			guess[3] = searched_words[i][3];
			if(hash_mode == HASH_6CHARS) {
				guess[4] = searched_words[i][4];
				guess[5] = searched_words[i][5];
			}
			
			letter_to_sym_permutation(guess, 0, strlen(guess), hashes, 1, 
				hash_mode, found_words, max_guesses);
			
			//try variations in cases of the words
			//case 1: first character to upper
			if(isalpha(searched_words[i][0]) && (guess[0] != 
				toupper(searched_words[i][0]))) {
				guess[0] = toupper(searched_words[i][0]);
				letter_to_sym_permutation(guess, 0, strlen(guess), hashes, 1,
					hash_mode, found_words, max_guesses);
			}

			//case 2: all characters to upper
			for(int k=0; k<answ_word_len; k++) {
				if(isalpha(searched_words[i][k])) {
					guess[k] = toupper(searched_words[i][k]);
				}
			}
			letter_to_sym_permutation(guess, 0, strlen(guess), hashes, 1, 
				hash_mode, found_words, max_guesses);
		}
	}
}


void brute_force_lowercase_alpha(BYTE **hashes, HASH_MODE hash_mode, 
	char **found_words, int max_guesses) {
	
	//adjust length of string based on the hash that we have 
	//and number of hashes
	char guess_template4[] = "    ";
	char guess_template6[] = "      ";
	char *guess;
	int char6_loop;
	if(hash_mode == HASH_4CHARS) {
		guess = &guess_template4[0];
		char6_loop = NUM_ALPHA-1;
	} else {
		guess = &guess_template6[0];
		char6_loop = 0;
	}
	
	//guess the passwords using a brute force on all lowercase alphabets
	for(int i=0; i<NUM_ALPHA; i++) {
		for(int j=0; j<NUM_ALPHA; j++) {
			for(int k=0; k<NUM_ALPHA; k++) {
				for(int p=0; p<NUM_ALPHA; p++) {
					for(int a=char6_loop; a<NUM_ALPHA; a++) {
						for(int b=char6_loop; b<NUM_ALPHA; b++) {
							//adds the character to the guess
							guess[0] = 'a' + i;
							guess[1] = 'a' + j;
							guess[2] = 'a' + k;
							guess[3] = 'a' + p;
							if(hash_mode == HASH_6CHARS) {
								guess[4] = 'a' + a;
								guess[5] = 'a' + b;
							}
							
							//checks if guess and its symbol variations 
							//are correct
							letter_to_sym_permutation(guess, 0, strlen(guess), 
								hashes, 1, hash_mode, found_words, max_guesses);
							
							//try variations of the word 
							//case 1: first character to upper
							guess[0] = toupper(guess[0]);
							//printf("%s ", char4_guess);
							letter_to_sym_permutation(guess, 0, strlen(guess), 
								hashes, 1, hash_mode, found_words, max_guesses);
					
							//case 2: all characters to upper
							for (int m=1; m<strlen(guess); m++) {
								guess[m] = toupper(guess[m]);
							}
							letter_to_sym_permutation(guess, 0, strlen(guess), 
								hashes, 1, hash_mode, found_words, max_guesses);
						}
					}
				}
			}
		}
	}
}

void adjust_upper_to_lower(char *guess, int position, int i) {
	if (i<NUM_ALPHA) {
		guess[position] = 'A' + i;
	} else {
		guess[position] = 'A' + i + ASCII_UPPER_TO_LOWER;
	}
}

void brute_force_mix_alpha(BYTE **hashes, HASH_MODE hash_mode, 
	char **found_words, int max_guesses) {
	//adjust length of string based on the hash that we have 
	//and number of hashes
	char guess_template4[] = "    ";
	char guess_template6[] = "      ";
	char *guess;
	int char6_loop;
	if(hash_mode == HASH_4CHARS) {
		guess = &guess_template4[0];
		char6_loop = NUM_UPPER_LOWER_ALPHA-1;
	} else {
		guess = &guess_template6[0];
		char6_loop = 0;
	}
	for(int i=0; i<NUM_UPPER_LOWER_ALPHA; i++) {
		for(int j=0; j<NUM_UPPER_LOWER_ALPHA; j++) {
			for(int k=0; k<NUM_UPPER_LOWER_ALPHA; k++) {
				for(int p=0; p<NUM_UPPER_LOWER_ALPHA; p++) {
					for(int a=char6_loop; a<NUM_UPPER_LOWER_ALPHA; a++) {
						for(int b=char6_loop; b<NUM_UPPER_LOWER_ALPHA; b++) {
							
							//skip over parts that are all lower case
							if(i>=NUM_ALPHA && j>=NUM_ALPHA &&
								k>=NUM_ALPHA && p>=NUM_ALPHA) {
								continue;
							}
							
							//adds the character to the guess
							adjust_upper_to_lower(guess, 0, i);
							adjust_upper_to_lower(guess, 1, j);
							adjust_upper_to_lower(guess, 2, k);
							adjust_upper_to_lower(guess, 3, p);
							if(hash_mode == HASH_6CHARS) {
								adjust_upper_to_lower(guess, 4, a);
								adjust_upper_to_lower(guess, 5, b);
							}
							
							//checks if guess and its symbol variations 
							//are correct
							letter_to_sym_permutation(guess, 0, strlen(guess), 
								hashes, 0, hash_mode, found_words, max_guesses);
						}
					}
				}
			}
		}
	}
}

void brute_force_numbers(BYTE **hashes, HASH_MODE hash_mode, 
	char **found_words, int max_guesses) {
	char guess_template4[] = "    ";
	char guess_template6[] = "      ";
	char *guess;
	int char6_loop;
	if(hash_mode == HASH_4CHARS) {
		guess = &guess_template4[0];
		char6_loop = NUM_DIGITS-1;
	} else {
		guess = &guess_template6[0];
		char6_loop = 0;
	}
	for(int i=0; i<NUM_DIGITS; i++) {
		for(int j=0; j<NUM_DIGITS; j++) {
			for(int k=0; k<NUM_DIGITS; k++) {
				for(int p=0; p<NUM_DIGITS; p++) {
					for(int a=char6_loop; a<NUM_DIGITS; a++) {
						for(int b=char6_loop; b<NUM_DIGITS; b++) {
							//adds the character to the guess
							guess[0] = '0' + i;
							guess[1] = '0' + j;
							guess[2] = '0' + k;
							guess[3] = '0' + p;
							if(hash_mode == HASH_6CHARS) {
								guess[4] = '0' + a;
								guess[5] = '0' + b;
							}
							if((check_guess(guess, hashes, found_words) > max_guesses) && (max_guesses >= 0)) {
								printf("yay");
								exit(EXIT_SUCCESS);
							}
						}
					}
				}
			}
		}
	}
}


BYTE **read_hash_file(char *hash_file, int num_hashes) {
	int i;
	FILE *fileptr;
	char *buffer;
	long file_len;
	 
	//processes the hash file
	fileptr = fopen(hash_file, "rb");
	fseek(fileptr, 0, SEEK_END);
	file_len = ftell(fileptr);
	rewind(fileptr);
	
	//stores hashes in the buffer
	buffer = malloc((file_len) * sizeof(char));
	fread(buffer, file_len, 1, fileptr);
	
	fclose(fileptr);
	
	//initialise array to store encoded hexadecimal words
	BYTE **hashes = malloc(num_hashes * sizeof(*hashes));
	for(i=0; i<num_hashes; i++) {
		hashes[i] = malloc(BYTES_IN_HASH * sizeof(BYTE));
	}
	
	//put the encoded hexadecimals into the array seperated by words
	int word_count = 0;
	int index = 0;
	for(i=0; i<file_len; i++) {
		hashes[word_count][index] = buffer[i];
		index += 1;
		
		//reset bytes counted after every 32 bytes (after every word)
		if (index == BYTES_IN_HASH) {
			index = 0;
			word_count += 1;
		}
		
	}
	
	free(buffer);
	
	return hashes;
}

int main(int argc, char* argv[]) {
	int max_guesses = -1;
	if(argc == 2) {
		max_guesses = atoi(argv[1]);
	}
	
	if(argc == 3) {
		compare_pass_to_hash(argv[1], argv[2]);
		return 0;
	}
	
	//reads the files containg the hash of the passwords
	BYTE **char4_hashes = read_hash_file("pwd4sha256", NUM_CHAR4_HASHES);
	BYTE **char6_hashes = read_hash_file("pwd6sha256", NUM_CHAR6_HASHES);
	
	//creates an array of words found
	char **found_words = malloc((NUM_CHAR4_HASHES + NUM_CHAR6_HASHES) 
		* sizeof(*found_words));
	for(int i=0; i<NUM_CHAR4_HASHES; i++) {
		found_words[i] = malloc((4+1) * sizeof(char));
	}
	for(int i=NUM_CHAR4_HASHES; i<NUM_CHAR4_HASHES + NUM_CHAR6_HASHES; i++) {
		found_words[i] = malloc((6+1) * sizeof(char));
	}
	
	//makes guesses on hashed 4 character passwords
    guess_with_file("common_passwords.txt", char4_hashes, HASH_4CHARS, 
    	found_words, max_guesses);
    guess_with_file("dict4words.txt",char4_hashes, HASH_4CHARS, found_words, max_guesses);
    brute_force_lowercase_alpha(char4_hashes, HASH_4CHARS, found_words, max_guesses);
    brute_force_numbers(char4_hashes, HASH_4CHARS, found_words, max_guesses);
    brute_force_mix_alpha(char4_hashes, HASH_4CHARS, found_words, max_guesses);
    
    //makes guesses on hashed 6 character passwords
    guess_with_file("common_passwords.txt", char6_hashes, HASH_6CHARS, 
    	found_words, max_guesses);
    guess_with_file("dict6words.txt",char6_hashes, HASH_6CHARS, found_words, max_guesses);
    brute_force_numbers(char6_hashes, HASH_6CHARS, found_words, max_guesses);
    brute_force_lowercase_alpha(char6_hashes, HASH_6CHARS, found_words, max_guesses);
    brute_force_mix_alpha(char6_hashes, HASH_6CHARS, found_words, max_guesses);
	return 0;
}

	
	
	

