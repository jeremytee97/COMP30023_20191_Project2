#ifndef CRACK_H
#define CRACK_H

#define MAX_KEYWORDS 95
#define MAX_ALPHABETS 52
#define MAX_LOWERCASE_ALPHABETS 26
#define MAX_NUMBERS 10

#define PWD4_GUESS_LENGTH 4
#define PWD6_GUESS_LENGTH 6

#define SMART_GUESS_WORD_LEN 6
#define MAX_COMBINATION_PER_CHAR 6
#define NUM_PWD4SHA256 10
#define NUM_PWD6SHA256 20

#define PWD4_FILENAME "pwd4sha256"
#define PWD6_FILENAME "pwd6sha256"
#define COMMON_PASS_FILENAME "common_passwords.txt"

//FOR SMART GUESS
#define ALPHA_PASS 0
#define ALPHANUMERIC_PASS 1
#define NUMERIC_PASS 2

//for character generation
#define NUMERIC_GUESS 900 //cummulative distribution alphabet 90% (0-899), number 10% (900-999)

//distribution of 82% alphabets, 11% alphanumeric and remaining is numeric passwords
#define PERCENTAGE_ALPHABETS_PASSWORD 0.82
#define PERCENTAGE_ALPHANUMERIC_PASSWORD 0.11


//define max guesses to generate before going with brute force
#define MAX_ALPHABETS_COMBINATIONS 308915776  //26^6 combinations
#define MAX_ALPHANUMERIC_COMBINATIONS 2147483647 //max int capacity as 36^6 cause overflow
#define MAX_NUMBERS_COMBINATIONS 1000000 //10^6 combinations
               
/*Function declaration*/

//=========== USE FOR ARG2 ===========
//compare the words in a given with the hashfile by looping every word and call compareHashes method
void compareAllGuesses(char* filename, BYTE** file, int num_hashes);

//=========== USE FOR ARG1 ===========
//generate x number of password
void generate_password(int numOfGuesses);

//=========== USE FOR SMART GUESSES ===========

//smart attack, generate x number of passwords based on statistics of common_password.txt
void generate_similar_words(int* numGuessRemaining);

//split numGuessRemaining into 3 different sizes - 88% alphabets, 11% alphanumeric, the rest is for numeric guesses
int calculate_distribution(int numGuessRemaining, int* nAlpha, int* nAlphaNum, int* nNumbers);

//generate a character based on the type, index
char characterGenerator(int roll, int index, int type, int flag);

//generate x number words for a given type
void generate_word(int numGuessRemaining, int type);

int randomNumGenerator();

//=========== USE FOR DICTIONARY ATTACK ===========

//perform dictionary attack by using inputs from common_passwords.txt
int dictionaryAttack(int numGuessRequired);

//generate suffix for a given prefix of length < 6
void generate_suffix_and_password(char* suffix, int suffix_length, char* prefix, int* numGuessRemaining);

//=========== USE FOR BRUTE FORCE =============
void bruteForce(int* numGuessRemaining);

//=========== USES SHA256 METHOD ===========

//read a given hashfile into the buffer
int readHashFile(char* filename, BYTE*** buffer);

//hash a given password and return it
BYTE* hashGuess(BYTE* guess, int guess_length);

//compare a given hash with the file buffer and prints it out if it is found
int compareHashes(BYTE** file, BYTE* guess, int num_hashes, int guess_length);


//============ USE FOR ARG0 =================
//used for arg0 brute force
void generateFourCharPass(int maxlen, BYTE** file, int numberOfHash);

//used for arg0 brute force
void generateSixCharPass(int maxlen, BYTE** file, int numberOfHash);
#endif
