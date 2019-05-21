
#ifndef CRACK_H
#define CRACK_H

#define MAX_KEYWORDS 95
#define MAX_ALPHABETS 52
#define MAX_LOWERCASE_ALPHABETS 26

#define PWD4_GUESS_LENGTH 4
#define PWD6_GUESS_LENGTH 6

#define SMART_GUESS_WORD_LEN 6
#define NUM_PWD4SHA256 10
#define NUM_PWD6SHA256 20

#define PWD4_FILENAME "pwd4sha256"
#define PWD6_FILENAME "pwd6sha256"
#define COMMON_PASS_FILENAME "common_passwords.txt"


/*Function declaration*/
int compareHashes(BYTE** file, BYTE* guess, int num_hashes, int guess_length);

void compareAllGuesses(char* guess, BYTE** file, int num_hashes);

void generateGuess(int numOfGuesses);

void generate_similar_words(char* word, int numGuessRemaining);

int dictionaryAttack(int numGuessRequired);

char* reverseWord(char* suffix);

void generateFourCharPass(int maxlen, BYTE** file, int numberOfHash);

void generateSixCharPass(int maxlen, BYTE** file, int numberOfHash);

int bruteImpl(char* str, int index, int maxDepth, char* prefix, int numGuessRequired, int numGuessMade);

int readHashFile(char* filename, BYTE*** buffer);

BYTE* hashGuess(BYTE* guess, int guess_length);

#endif // SHA256_H
