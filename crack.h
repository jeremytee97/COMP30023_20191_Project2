
#ifndef CRACK_H
#define CRACK_H

#define MAX_KEYWORDS 95
#define NUM_PWD4SHA256 10
#define NUM_PWD6SHA256 20
#define PWD4_FILENAME "pwd4sha256"


/*Function declaration*/
void compareHashes(BYTE** file, BYTE* guess, int num_hashes, int guess_length);

void generate(int maxlen, BYTE** file);

BYTE** readfile(char* filename, int num_hashes);

BYTE* hashGuess(BYTE* guess, int guess_length);

#endif // SHA256_H
