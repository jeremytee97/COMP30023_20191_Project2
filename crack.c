/*
    Computer System - Project 2 (Password Cracker)
    Author: Jeremy Tee (856782)
    Purpose:
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <unistd.h>
#include "sha256.h"
#include "crack.h"

static const int MAX_LENGTH = 4;
// Print all combinations of the given alphabet up to length n.
//
// The best way to test this program is to output to /dev/null, otherwise
// the file I/O will dominate the test time.

const BYTE alphabet[MAX_KEYWORDS] = "abcdefghijklmnopqrstuvwxyz"
                       "0123456789"
                       " ,./;'[]\\-=`<>?:\"{}|~!@#$%^&*()_+"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/* const BYTE similarCharacters = {'a', 'A', '4', '@'}, {'b', 'B', '?', '6'}, {'c', 'C', '('}, {'d', 'D', '?'}, {'e', 'E', '3'},
{'f', 'F'}, {'g', 'G'}, {''}
 */
//" ,./;'[]\\-=`<>?:\"{}|~!@#$%^&*()_+"
int main(int argc, char *argv[])
{
    if (argc < 2) {
      BYTE** file = readHashFile(PWD4_FILENAME, NUM_PWD4SHA256);
      generateFourCharPass(MAX_LENGTH, file, NUM_PWD4SHA256);
      free(file);
      printf("END OF KEYWORD 4\n");
      BYTE** file2 = readHashFile(PWD6_FILENAME, NUM_PWD6SHA256);
      generateSixCharPass(6, file2, NUM_PWD6SHA256);
      free(file2);
    }
    return 0;
}


BYTE** readHashFile(char* filename, int num_hashes){
   
    FILE *fp;
    BYTE **buffer = (BYTE **)malloc(num_hashes * sizeof(BYTE *)); 
    for (int i=0; i < num_hashes; i++){
         buffer[i] = (BYTE *)malloc(SHA256_BLOCK_SIZE+1);
    }
    
    fp = fopen(filename, "rb");
    int i = 0;
    if (fp != NULL){
        int read = 0;
        while((read = fread(buffer[i], SHA256_BLOCK_SIZE, 1, fp)) > 0){
            i++;
        }
    }
    fclose(fp);
    return buffer;
}


int compareHashes(BYTE** file, BYTE* guess, int num_hashes, int guess_length){
    int test;
    BYTE* hashed_guess = hashGuess(guess, guess_length);
    for(int i = 0; i < num_hashes; i++){
        test = memcmp(file[i], hashed_guess, SHA256_BLOCK_SIZE);
        if(test == 0){
            printf("%s %d\n", guess, i);
            return 1;
        }
    }
    free(hashed_guess);
    return 0;
}

BYTE* hashGuess(BYTE* guess, int guess_length){
    BYTE* buffer = (BYTE*)malloc(SHA256_BLOCK_SIZE+1);
    SHA256_CTX ctx;
    sha256_init(&ctx);
	sha256_update(&ctx, guess, guess_length);
	sha256_final(&ctx, buffer);

    return buffer;
}

/* Brute force generating all possible 4 keyword password */
void generateFourCharPass(int maxlen, BYTE** file, int numberOfHash){
    int   len      = maxlen;
    BYTE *buffer   = malloc((maxlen + 1));

    if (buffer == NULL) {
        fprintf(stderr, "Cannot allocate memory for buffer");
        exit(1);
    }

    // This for loop generates all 1 letter patterns, then 2 letters, etc,
    // up to the given maxlen.
    // The stride is one larger than len because each line has a '\0'.
    int stride = len+1;
    int bufLen = stride;

    // Initialize buffer
    memset(buffer, '\0', bufLen);
    int numOfCorrectGuesses = 0;
    for(int i = 0; i < MAX_KEYWORDS; i++){
        for(int j = 0; j < MAX_KEYWORDS; j++){
            for(int k = 0; k < MAX_KEYWORDS; k++){
                for(int l = 0; l < MAX_KEYWORDS; l++){
                    buffer[0] = alphabet[i];
                    buffer[1] = alphabet[j];
                    buffer[2] = alphabet[k];
                    buffer[3] = alphabet[l];
                    numOfCorrectGuesses += compareHashes(file, buffer, NUM_PWD4SHA256, MAX_LENGTH);
                    memset(buffer, '\0', bufLen);
                    if(numOfCorrectGuesses == numberOfHash){
                        free(buffer);
                        return;
                    }
                }
            }
        }
    }
    // Clean up
    free(buffer);
}


void smartGuesses(int maxlen, BYTE** file, int numOfHash){
    BYTE *buffer   = malloc((maxlen + 1));

    if (buffer == NULL) {
        fprintf(stderr, "Cannot allocate memory for buffer");
        exit(1);
    }


    // This for loop generates all 1 letter patterns, then 2 letters, etc,
    // up to the given maxlen.
    // The stride is one larger than len because each line has a '\0'.
    int stride = maxlen+1;
    int bufLen = stride;

    // Initialize buffer
    memset(buffer, '\0', bufLen);
    int numOfCorrectGuesses = 0;

    
    //try dictionary attack first

    char* filename = COMMON_PASS_FILENAME; /* should check that argc > 1 */
    FILE* common_password = fopen(filename, "r"); /* should check the result */
    char line[256];

    fclose(common_password);

}


/* Brute force generating all possible 4 keyword password */
void generateSixCharPass(int maxlen, BYTE** file, int numberOfHash){
    int   len      = maxlen;
    BYTE *buffer   = malloc((maxlen + 1));

    if (buffer == NULL) {
        fprintf(stderr, "Cannot allocate memory for buffer");
        exit(1);
    }

    // This for loop generates all 1 letter patterns, then 2 letters, etc,
    // up to the given maxlen.
    // The stride is one larger than len because each line has a '\0'.
    int stride = len+1;
    int bufLen = stride;

    BYTE test[7] = {'t', 'e', 'e', 'j', '1', ' '};
    int numOfCorrectGuesses = 0;
    numOfCorrectGuesses = compareHashes(file, test, NUM_PWD6SHA256, 6);

    // Initialize buffer
    memset(buffer, '\0', bufLen);
    for(int i = 0; i < MAX_KEYWORDS; i++){
        for(int j = 0; j < MAX_KEYWORDS; j++){
            for(int k = 0; k < MAX_KEYWORDS; k++){
                for(int l = 0; l < MAX_KEYWORDS; l++){
                    for(int m = 0; m < MAX_KEYWORDS; m++){
                        for(int n = 0; n < MAX_KEYWORDS; n++){
                            buffer[0] = alphabet[i];
                            buffer[1] = alphabet[j];
                            buffer[2] = alphabet[k];
                            buffer[3] = alphabet[l];
                            buffer[4] = alphabet[m];
                            buffer[5] = alphabet[n];
                            numOfCorrectGuesses += compareHashes(file, buffer, NUM_PWD6SHA256, 6);
                            //printf("%s\n", buffer);
                            memset(buffer, '\0', bufLen);
                            if(numOfCorrectGuesses == numberOfHash){
                                free(buffer);
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
    // Clean up
    free(buffer);
}
