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


const BYTE smartGuess[52] = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const BYTE alphabets[MAX_ALPHABETS] = "abcdefghijklmnopqrstuvwxyz";

const char similar_character_mapping[MAX_ALPHABETS][MAX_SIMILAR_CHARACTER+1] = {
    "A4@", "B?68","C(","D?","E3","F","G","H","I!|1","J","K","L|1","M","N&^",
    "O0*","P?","Q9","R2","S$52","T7%","U","V","W","X*","Y","Z"}
    ;

char symbolsPool[12] = "?|~!@#$%^&*+";

char numberPool[10] =  "0123456789";

//" ,./;'[]\\-=`<>?:\"{}|~!@#$%^&*()_+"
int main(int argc, char *argv[])
{
    if (argc == 2){
        int numOfGuesses = atoi(argv[1]);
        smartGuesses(numOfGuesses);
    }

    else if (argc == 1){
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
            printf("%s %d\n", guess, i+1+10);
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


void smartGuesses(int numGuessRequired){
    //try dictionary attack using common_password.txt
    //if length 6 just print, else if < 6, combine numbers and punctuation
    int numGuessMade = 0;
    numGuessMade += dictionaryAttack(numGuessRequired);
    
    printf("%d\n", numGuessMade);

    //update guess required
    numGuessRequired -= numGuessMade;
    while(numGuessRequired != 0){
        //do smtg else

        numGuessRequired --;
    }
}

int dictionaryAttack(int numGuessRequired){
    //include '\0'
    int bufferLen = SMART_GUESS_WORD_LEN + 1;

    int numGuessMade = 0;

    //read common_password file
    FILE *file = fopen (COMMON_PASS_FILENAME,"r");
    if (file != NULL){
        char line [128]; 
        bzero(line, 128);
        char *buffer   = malloc(bufferLen);

        if (buffer == NULL) {
            fprintf(stderr, "Cannot allocate memory for buffer");
            exit(1);
        }
        
         //try dictionary attack first
        while (fgets(line, sizeof(line), file) != NULL ){
            int wordLen = strlen(line);

            //ignore words with length > 6 + 1 (take account '\n' character)
            if(wordLen > SMART_GUESS_WORD_LEN + 1){
                continue;
            }
        
            //copy string without '\n'
            strncpy(buffer, line, wordLen - 1);

            //clear line and buffer for next word (safety purpose)
            bzero(line, 128);
            
            //if it is a 6 character guess, output and move on
            if(strlen(buffer) == 6){
                printf("%s\n", buffer);
                numGuessMade++;
            // string length < 6
            } else {
                int length_suffix =  SMART_GUESS_WORD_LEN - strlen(buffer);
                char* suffix_buff = malloc(length_suffix + 1);
                memset(suffix_buff, 0, length_suffix + 1);
                numGuessMade = bruteImpl(suffix_buff, 0, length_suffix, buffer, numGuessRequired, numGuessMade);
                free(suffix_buff);
            }
            //reset buffer for next word
            memset(buffer, '\0', bufferLen);
            if (numGuessMade == numGuessRequired){
                return numGuessMade;
            }
        }
        fclose(file);
        free(buffer);
        return numGuessMade;
    } else{
        perror("Common_password.txt not found");
        return 0;
    }
}


int bruteImpl(char* suffix, int index, int maxDepth, char* prefix, int numGuessRequired, int numGuessMade){
    //if suffix length = 2 (1 number, 1 symbol)
    //if suffix length = 1 (1 number)
    char* charPool;
    int poolSize;
    if(index == 0){
       charPool = numberPool;
       poolSize = 10;
    } else {
       charPool = symbolsPool;
       poolSize = 12;
    }
    for (int i = 0; i < poolSize; i++){
        suffix[index] = charPool[i];
        if (index == maxDepth - 1){
            printf("%s%s\n", prefix, suffix);
            if(maxDepth == 2){
                numGuessMade++;
                if(numGuessMade == numGuessRequired){
                    return numGuessMade;
                }
                char* reversedSuffix = reverseWord(suffix);
                printf("%s%s\n", prefix, reversedSuffix);
                free(reversedSuffix);
            }
            numGuessMade++;
            if(numGuessMade == numGuessRequired){
                return numGuessMade;
            }
        } else {
            if(bruteImpl(suffix, index + 1, maxDepth, prefix, numGuessRequired, numGuessMade) == numGuessRequired){
                return numGuessMade;
            }
        }
    }
    return numGuessMade;
}

char* reverseWord(char* suffix){
    char* suffix_buffer = malloc(strlen(suffix)+1);
    memset(suffix_buffer, '\0', strlen(suffix)+1);
    strcpy(suffix_buffer, suffix);
    char tmp;
    int last_index_suffix = strlen(suffix) - 1;
    for(int i = 0; i < last_index_suffix;i++){
       tmp = suffix_buffer[i];
       suffix_buffer[i] = suffix_buffer[last_index_suffix];
       suffix_buffer[last_index_suffix] = tmp;
       last_index_suffix--;
   }
   return suffix_buffer;
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
    for(int i = 4; i < 52; i++){
        for(int j = 0; j < 52; j++){
            for(int k = 0; k < 52; k++){
                for(int l = 0; l < 52; l++){
                    for(int m = 0; m < 52; m++){
                        for(int n = 0; n < 52; n++){
                            buffer[0] = smartGuess[i];
                            buffer[1] = smartGuess[j];
                            buffer[2] = smartGuess[k];
                            buffer[3] = smartGuess[l];
                            buffer[4] = smartGuess[m];
                            buffer[5] = smartGuess[n];
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
/* void bruteSequential(int maxLen){
    char* buf = malloc(maxLen + 1);
    memset(buf, 0, maxLen + 1);
    bruteImpl(buf, 0, maxLen);
    free(buf);
} */
