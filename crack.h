
#ifndef CRACK_H
#define CRACK_H

#define MAX_KEYWORDS 95
#define MAX_ALPHABETS 26

#define MAX_SIMILAR_CHARACTER 4

#define SMART_GUESS 90
#define SMART_GUESS_WORD_LEN 6
#define NUM_PWD4SHA256 10
#define NUM_PWD6SHA256 20

#define PWD4_FILENAME "pwd4sha256"
#define PWD6_FILENAME "pwd6sha256"
#define COMMON_PASS_FILENAME "common_passwords.txt"


/*Function declaration*/
int compareHashes(BYTE** file, BYTE* guess, int num_hashes, int guess_length);

void generateGuess(int numOfGuesses);

int dictionaryAttack(int numGuessRequired);

char* reverseWord(char* suffix);

void generateFourCharPass(int maxlen, BYTE** file, int numberOfHash);

void generateSixCharPass(int maxlen, BYTE** file, int numberOfHash);

int bruteImpl(char* str, int index, int maxDepth, char* prefix, int numGuessRequired, int numGuessMade);

BYTE** readHashFile(char* filename, int num_hashes);

BYTE* hashGuess(BYTE* guess, int guess_length);

#endif // SHA256_H
