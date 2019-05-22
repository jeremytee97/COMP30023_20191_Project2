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
#include <strings.h>
#include <unistd.h>
#include <math.h>
#include "sha256.h"
#include "crack.h"

const BYTE allchar[MAX_KEYWORDS] = "abcdefghijklmnopqrstuvwxyz"
                       "0123456789"
                       " ,./;'[]\\-=`<>?:\"{}|~!@#$%^&*()_+"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ";


const BYTE alphabets[MAX_ALPHABETS] = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const BYTE lower_case_alpha[MAX_LOWERCASE_ALPHABETS] = "abcdefghijklmnopqrstuvwxyz";
/* 
const char similar_character_mapping[MAX_LOWERCASE_ALPHABETS][MAX_SIMILAR_CHARACTER+1] = {
    "A4@", "B?68","C(","D?","E*3","F","G","H","I!|1","J","K","L|1","M","N&^",
    "O0*","P?","Q9","R2","S$52","T7%","U","V","W","X*","Y","Z"}
    ; */

char similar_p[4] = "p\0";

char similar_a[4] = "a4\0";

char similar_s[5] = "52\0";

char similar_w[3] = "w\0";

char similar_o[4] = "0\0";

char symbolsPool[13] = "?|~!@#$%^&*+\0";

char numberPool[11] =  "0123456789\0";

int main(int argc, char *argv[]){
    //generate x amount of guesses
    if (argc == 2){
        int numOfGuesses = atoi(argv[1]);
        generateGuess(numOfGuesses);
    
    //argv[2] = guess file, arg[3] = hashedfile
    }else if(argc == 3){
        BYTE** hashed_file;
        int num_hashes;
        num_hashes = readHashFile(argv[2], &hashed_file);
        compareAllGuesses(argv[1],hashed_file, num_hashes);
        free(hashed_file);
    
    //will not be tested (use to generate guesses for pwd4sha256/ pwd6sha256)
    }else if (argc == 1){
        BYTE **file, **file2; 
        int num_pwd4sha, num_pwd6sha;
        num_pwd4sha = readHashFile(PWD4_FILENAME, &file);
        generateFourCharPass(PWD4_GUESS_LENGTH, file, num_pwd4sha);
        free(file);
        num_pwd6sha = readHashFile(PWD6_FILENAME, &file2);
        generateSixCharPass(PWD6_GUESS_LENGTH, file2, num_pwd6sha);
        free(file2);
    }
    return 0;
}

void compareAllGuesses(char* filename, BYTE** hashed_file, int num_hashes){
    FILE *fp;
    //usage: read from fgets file
    char line[100001];
    bzero(line, 100001);

    //usage: convert line to byte (unsigned char) for formula purposes
    BYTE guess[100001];
    bzero(guess, 100001);

    fp = fopen(filename, "r");
    if(fp != NULL){
        //for own record purposes
        int numOfCorrectGuesses = 0;
        while (fgets(line, sizeof(line), fp) != NULL ){
            //length of guess (without \n character)
            int wordLen = strlen(line) - 1;
            memcpy(guess, line, wordLen);
            numOfCorrectGuesses += compareHashes(hashed_file, guess, num_hashes, wordLen);

            //flush buffer after usage
            bzero(line, 100001);
            bzero(guess, 100001);
        }
    } else {
        fprintf(stderr, "File not found");
    }
    fclose(fp);
}

int readHashFile(char* filename, BYTE*** buffer){
    FILE *fp;

    //store a line
    BYTE line[SHA256_BLOCK_SIZE];
    bzero(line, SHA256_BLOCK_SIZE);

    //first read to store the total num_hashes
    fp = fopen(filename, "rb");
    int num_hashes = 0;
    if (fp != NULL){
        int read = 0;
        while((read = fread(line, SHA256_BLOCK_SIZE, 1, fp)) > 0){
            num_hashes++;
        }
    }
    fclose(fp);

    //dynamic allocation based on num_hashes
    *buffer = (BYTE**)malloc(num_hashes * sizeof(BYTE *)); 
    if (*buffer == NULL){
        fprintf(stderr, "Cannot allocate memory for hashed_file");
        exit(1);
    }
    for (int i=0; i < num_hashes; i++) {
        (*buffer)[i] = (BYTE*)malloc(SHA256_BLOCK_SIZE+1);
        if ((*buffer)[i] == NULL){
            fprintf(stderr, "Cannot allocate memory for hashed_file");
            exit(1);
        }
    }

    //second read to store hashes in buffer
    fp = fopen(filename, "rb");
    int i = 0;
    if (fp != NULL){
        int read = 0;
        while((read = fread((*buffer)[i], SHA256_BLOCK_SIZE, 1, fp)) > 0){
            i++;
        }
    }
    fclose(fp);
    return num_hashes;
}

int compareHashes(BYTE** file, BYTE* guess, int num_hashes, int guess_length){
    int test;
    BYTE* hashed_guess = hashGuess(guess, guess_length);
    for(int i = 0; i < num_hashes; i++){
        test = memcmp(file[i], hashed_guess, SHA256_BLOCK_SIZE);
        if(test == 0){
            printf("%s %d\n", guess, i+1);
            free(hashed_guess);
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

//statistics of common_password.txt and other students hashes are in readme file
void generateGuess(int numGuessRequired){

    //try dictionary attack using common_password.txt
    int numGuessMade = 0;
    numGuessMade += dictionaryAttack(numGuessRequired);
    
    printf("\nNUM GUESS MADE FROM DICT ATTACK : %d\n", numGuessMade);

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

    //minimum need generate 1 combination per word
    int numGuessPerWord = (int)max(round(numGuessRequired/10000),1);
    int numGuessRemaining = numGuessRequired;
    printf("numGuessPerWord: %d\n", numGuessPerWord);

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

            //slice words if length > SMART_GUESS_WORD_LEN
            if(wordLen > SMART_GUESS_WORD_LEN + 1){
                strncpy(buffer, line, SMART_GUESS_WORD_LEN);

            //if less than or equals to SMART_GUESS_WORD_LEN, copy string without '\n'
            } else { 
                strncpy(buffer, line, wordLen - 1);
            }
        
            //clear line and buffer for next word (safety purpose)
            bzero(line, 128);
            
            //if it is a 6 character guess, output and move on
            if(strlen(buffer) == 6){
                generate_similar_words(buffer, &numGuessRemaining, numGuessPerWord);
            // string length < 6
            } else {
                /*int length_suffix =  SMART_GUESS_WORD_LEN - strlen(buffer);
                char* suffix_buff = malloc(length_suffix + 1);
                memset(suffix_buff, 0, length_suffix + 1);
                numGuessMade = bruteImpl(suffix_buff, 0, length_suffix, buffer, numGuessRequired, numGuessMade);
                free(suffix_buff);*/
            }
            //reset buffer for next word
            memset(buffer, '\0', bufferLen);
            if (numGuessRemaining == 0){
                return numGuessRemaining;
            }
        }
        fclose(file);
        free(buffer);
        return numGuessRemaining;
    } else{
        perror("Common_password.txt not found");
        return 0;
    }
}

void generate_similar_words(char* word, int* numGuessRemaining, int numGuessPerWord){
    char charCombination[SMART_GUESS_WORD_LEN][MAX_COMBINATION_PER_CHAR];
    memset(charCombination, '\0', sizeof(charCombination));
    generateGuessBuffer(charCombination, word);

    char guess[SMART_GUESS_WORD_LEN+1];
    bzero(guess, SMART_GUESS_WORD_LEN+1);

    for(int i = 0; i < strlen(charCombination[0]); i++){
        for(int j = 0; j < strlen(charCombination[1]); j++){
            for(int k = 0; k < strlen(charCombination[2]); k++){
                for(int l = 0; l < strlen(charCombination[3]); l++){
                    for(int m = 0; m < strlen(charCombination[4]); m++){
                        for(int n = 0; n < strlen(charCombination[5]); n++){
                            guess[0] = charCombination[0][i];
                            guess[1] = charCombination[1][j];
                            guess[2] = charCombination[2][k];
                            guess[3] = charCombination[3][l];
                            guess[4] = charCombination[4][m];
                            guess[5] = charCombination[5][n];
                            printf("%s\n", guess);
                            (*numGuessRemaining) --;
                            numGuessPerWord --;
                            if(numGuessPerWord == 0){
                                return;
                            }
                            if((*numGuessRemaining) == 0){
                                printf("SUCCESS!");
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

void generateGuessBuffer(char charCombination[][MAX_COMBINATION_PER_CHAR], char* word){
    for(int i = 0; i < SMART_GUESS_WORD_LEN; i++){
        charCombination[i][0] = word[i];
        strcat(charCombination[i], "ab");
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

float max(float x, float y){
    if(x > y){
        return x;
    }
    return y;
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
                    buffer[0] = allchar[i];
                    buffer[1] = allchar[j];
                    buffer[2] = allchar[k];
                    buffer[3] = allchar[l];
                    numOfCorrectGuesses += compareHashes(file, buffer, NUM_PWD4SHA256, PWD4_GUESS_LENGTH);
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
                            buffer[0] = alphabets[i];
                            buffer[1] = alphabets[j];
                            buffer[2] = alphabets[k];
                            buffer[3] = alphabets[l];
                            buffer[4] = alphabets[m];
                            buffer[5] = alphabets[n];
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
