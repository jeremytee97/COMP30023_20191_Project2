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
        for(int j = 0; j < SHA256_BLOCK_SIZE; j++){
            printf("%02x", file[i][j]);
        }
        printf("\n=====");
        for(int j = 0; j < SHA256_BLOCK_SIZE; j++){
            printf("%02x", hashed_guess[j]);
        }
        printf("\n=====");
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

/**
 * Generates all patterns of the alphabet up to maxlen in length.  This
 * function uses a buffer that holds alphaLen * alphaLen patterns at a time.
 * One pattern of length 5 would be "aaaaa\n".  The reason that alphaLen^2
 * patterns are used is because we prepopulate the buffer with the last 2
 * letters already set to all possible combinations.  So for example,
 * the buffer initially looks like "aaaaa\naaaab\naaaac\n ... aaa99\n".  Then
 * on every iteration, we write() the buffer out, and then increment the
 * third to last letter.  So on the first iteration, the buffer is modified
 * to look like "aabaa\naabab\naabac\n ... aab99\n".  This continues until
 * all combinations of letters are exhausted.
 */
void generate(int maxlen, BYTE** file)
{
    int   alphaLen = 95;
    int num_guesses_made = 0;
    int   len      = maxlen;
    BYTE *buffer   = malloc((maxlen + 1) * alphaLen * alphaLen);
    int  *letters  = malloc(maxlen * sizeof(int));

    if (buffer == NULL || letters == NULL) {
        fprintf(stderr, "Not enough memory.\n");
        exit(1);
    }

    // This for loop generates all 1 letter patterns, then 2 letters, etc,
    // up to the given maxlen.
    // The stride is one larger than len because each line has a '\n'.
    int i;
    int stride = len+1;
    int bufLen = stride * alphaLen * alphaLen;

    // Initialize buffer to contain all first letters.
    memset(buffer, alphabet[0], bufLen);

    // Now write all the last 2 letters and newlines, which
    // will after this not change during the main algorithm.
    {
        // Let0 is the 2nd to last letter.  Let1 is the last letter.
        int let0 = 0;
        int let1 = 0;
        for (i=len-2;i<bufLen;i+=stride) {
            buffer[i]   = alphabet[let0];
            buffer[i+1] = alphabet[let1++];
            buffer[i+2] = '\n';
            if (let1 == alphaLen) {
                let1 = 0;
                let0++;
                if (let0 == alphaLen)
                    let0 = 0;
            }
        }
    }

    // Set all the letters to 0.
    for (i=0;i<len;i++)
        letters[i] = 0;

    // Now on each iteration, increment the the third to last letter.
    i = len-3;
    do {
        char c;
        int  j;

        // Increment this letter.
        letters[i]++;

        // Handle wraparound.
        if (letters[i] >= alphaLen)
            letters[i] = 0;

        // Set this letter in the proper places in the buffer.
        c = alphabet[letters[i]];
        for (j=i;j<bufLen;j+=stride)
            buffer[j] = c;

        if (letters[i] != 0) {
            // No wraparound, so we finally finished incrementing.
            // Write out this set.  Reset i back to third to last letter.
            //write(STDOUT_FILENO, buffer, bufLen);
            
            compareHashes(file, buffer, NUM_PWD4SHA256, MAX_LENGTH);
            num_guesses_made++;

            printf("\n NUM OF GUESS %d \n", num_guesses_made);
            i = len - 3;
            continue;
        }

        // The letter wrapped around ("carried").  Set up to increment
        // the next letter on the left.
        i--;
        // If we carried past last letter, we're done with this
        // whole length.
        if (i < 0)
            break;
    } while(1);

    // Clean up.
    free(letters);
    free(buffer);
}
