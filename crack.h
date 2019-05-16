
#ifndef CRACK_H
#define CRACK_H

#define MAX_KEYWORDS 95
#define SMART_GUESS 90
#define NUM_PWD4SHA256 10
#define NUM_PWD6SHA256 20
#define PWD4_FILENAME "pwd4sha256"
#define PWD6_FILENAME "pwd6sha256"
#define COMMON_PASS_FILENAME "common_passwords.txt"


/*Function declaration*/
int compareHashes(BYTE** file, BYTE* guess, int num_hashes, int guess_length);

void generateFourCharPass(int maxlen, BYTE** file, int numberOfHash);

void generateSixCharPass(int maxlen, BYTE** file, int numberOfHash);

BYTE** readHashFile(char* filename, int num_hashes);

BYTE* hashGuess(BYTE* guess, int guess_length);

#endif // SHA256_H
