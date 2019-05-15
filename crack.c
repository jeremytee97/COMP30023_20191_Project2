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
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                       " ,./;'[]\\-=`<>?:\"{}|~!@#$%^&*()_+"
                       "0123456789";

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s Length\n", argv[0]);
        exit(1);
    }

    BYTE** file = readfile("pwd4sha256", NUM_PWD4SHA256);
    generate(atoi(argv[1]), file);
    
    return 0;
}


BYTE** readfile(char* filename, int num_hashes){
   
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


void compareHashes(BYTE** file, BYTE* guess, int num_hashes, int guess_length){
    int test;
    BYTE* hashed_guess = hashGuess(guess, guess_length);
    for(int i = 0; i < num_hashes; i++){
        test = memcmp(file[i], hashed_guess, SHA256_BLOCK_SIZE);
        if(test == 0){
            printf("%s %d\n", guess, i);
        }
    }
    free(hashed_guess);
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
void generateFourCharPass(int maxlen, BYTE** file){
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
    int numOfGuesses = 0;
    for(int i = 0; i < MAX_KEYWORDS; i++){
        for(int j = 0; j < MAX_KEYWORDS; j++){
            for(int k = 0; k < MAX_KEYWORDS; k++){
                for(int l = 0; l < MAX_KEYWORDS; l++){
                    buffer[0] = alphabet[i];
                    buffer[1] = alphabet[j];
                    buffer[2] = alphabet[k];
                    buffer[3] = alphabet[l];
                    compareHashes(file, buffer, NUM_PWD4SHA256, MAX_LENGTH);
                    memset(buffer, '\0', bufLen);
                    numOfGuesses++;
                }
            }
        }
    }
    printf("Num of guesses %d\n", numOfGuesses);
    // Clean up
    free(buffer);
}
