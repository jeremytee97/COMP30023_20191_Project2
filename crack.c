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
#include<time.h> 
#include "sha256.h"
#include "crack.h"

const BYTE allchar[MAX_KEYWORDS] = "abcdefghijklmnopqrstuvwxyz"
                       "0123456789"
                       " ,./;'[]\\-=`<>?:\"{}|~!@#$%^&*()_+"
                       "ABCDEFGHIJKLMNOPQRSTUVWXYZ";


const BYTE alphabets[MAX_ALPHABETS] = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

char lowercase_alphabets[MAX_LOWERCASE_ALPHABETS] = "abcdefghijklmnopqrstuvwxyz";

char numbers[MAX_NUMBERS] = "0123456789";

int main(int argc, char *argv[]){
    //generate x amount of guesses
    if (argc == 2){

        srand(time(NULL)); 
        int numOfGuesses = atoi(argv[1]);
        generate_password(numOfGuesses);
    
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
void generate_password(int numGuessRequired){

    //try dictionary attack using common_password.txt
    //if length < 6 append suffix to it
    int numGuessLeftAfterDictAttack = numGuessRequired;
    //numGuessLeftAfterDictAttack = dictionaryAttack(numGuessRequired);
    
    printf("%d\n", numGuessLeftAfterDictAttack);
    
    while(numGuessLeftAfterDictAttack != 0){
        //do smtg else
       generate_similar_words(&numGuessLeftAfterDictAttack);
    } 
}

int dictionaryAttack(int numGuessRemaining){
    //include '\0'
    int bufferLen = SMART_GUESS_WORD_LEN + 1;

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
                printf("%s\n", buffer);
                numGuessRemaining --;
            // string length < 6
            } else {
                int suffix_length =  SMART_GUESS_WORD_LEN - strlen(buffer);
                char* suffix_buff = malloc(suffix_length + 1);
                memset(suffix_buff, 0, suffix_length + 1);
                generate_suffix_and_password(suffix_buff, suffix_length, buffer, &numGuessRemaining);
                free(suffix_buff);
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

/*
'A': 5,'B': 4,'C': 4,'D': 3,'E': 2,'F': 1,'H': 1,'I': 3,'J': 2,'K': 1,'L': 6,'P': 4,'R': 4,'S': 9,'U': 1,'W': 3,
'a': 460,'b': 794,'c': 782,'d': 502,'e': 225,'f': 370,'g': 402,'h': 409,'i': 139,'j': 301,'k': 229,'l': 372,'m': 664,
'n': 249,'o': 133,'p': 586,'q': 70,'r': 433,'s': 1062,'t': 500,'u': 54,'v': 141,'w': 306,'x': 36,'y': 76,'z': 89})*/
void generate_similar_words(int* numGuessRemaining){
    int nAlpha, nAlphaNum, nNumbers;
    calculate_distribution(*numGuessRemaining, &nAlpha, &nAlphaNum, &nNumbers);

    //clear buffer for nAlpha
    char charCombination[SMART_GUESS_WORD_LEN][MAX_COMBINATION_PER_CHAR];
    memset(charCombination, '\0', sizeof(charCombination));
    
    generate_word(nAlpha, ALPHA_PASS);
    (*numGuessRemaining) --;

    //clear buffer for nAlphaNum
    memset(charCombination, '\0', sizeof(charCombination));
    
    generate_word(nAlphaNum, ALPHANUMERIC_PASS);
    (*numGuessRemaining) --;

/* //include uppercase letters into the pool
generate_password(charCombination, word, UPPERCASE);

//print passwords with uppercase
generate_pass(charCombination, numGuessPerWord - 1, &numGuessRemaining);

//clear buffer again
memset(charCombination, '\0', sizeof(charCombination));

//include special symbols into the pool
generate_pass_buffer(charCombination, word, SYMBOL);

//print password with symbols (1 only as distribution shows symbols dont appear frequently)
generate_pass(charCombination, 1, &numGuessRemaining); */
}

void calculate_distribution(int numGuessRemaining, int* nAlpha, int* nAlphaNum, int* nNumbers){
    *nAlpha = round(numGuessRemaining * PERCENTAGE_ALPHABETS_PASSWORD);
    *nAlphaNum = round(numGuessRemaining * PERCENTAGE_ALPHANUMERIC_PASSWORD);
    *nNumbers = numGuessRemaining - *nAlpha - *nAlphaNum;
}

void generate_word(int numGuessRemaining, int type){
    char guess[SMART_GUESS_WORD_LEN+1];
    bzero(guess, SMART_GUESS_WORD_LEN+1);
    int flag = 0;
    //generate alphabetical password
    if(type == ALPHA_PASS){
        for(int i = 0; i < SMART_GUESS_WORD_LEN; i++){
            //roll twice for each character, first is for which alphabet, second is whether upper or lowercase
            //percentage of these are based on statistics collected
            int roll = randomNumGenerator();
            char character = characterGenerator(roll, i, ALPHA_PASS, flag);
            guess[i] = character;
        }
        //printf("%s\n", guess);
        numGuessRemaining --;
        bzero(guess, SMART_GUESS_WORD_LEN+1);

    //generate alphanumeric password
    } else if(type == ALPHANUMERIC_PASS){
        for(int i = 0; i < SMART_GUESS_WORD_LEN; i++){
            //first roll to decide whether is num/alphabet
            //if alphabet, roll to decide which alphabet, and roll again to decide if its uppercase
            //if all is alphabet, last one must be num since it is alphanumeric
            int roll = randomNumGenerator();
            char character = characterGenerator(roll, i, ALPHANUMERIC_PASS, flag);
            guess[i] = character;
            if (isdigit(character) > 0){
                flag = 1;
            }
        }
        printf("%s\n", guess);
        numGuessRemaining --;
        bzero(guess, SMART_GUESS_WORD_LEN+1);
    }
}

char characterGenerator(int roll, int index, int type, int flag){
    char c = '\0';

    //if type is alphabets
    if(type == ALPHA_PASS){
        for(int i = 0; i < MAX_LOWERCASE_ALPHABETS; i++){
            if(roll <= (nAlpha_char_distribution[index][i]*1000)){
                c = lowercase_alphabets[i];
                break;
            }
        }
        int isUpper = randomNumGenerator();
        if(isUpper < (char_upper_distribution[0]*1000)){
            return c;
        }
        return toupper(c);
    
    //type is alphanumeric
    } else if (type == ALPHANUMERIC_PASS) {
        int roll2 = randomNumGenerator();
        //if its last character and still no number, make the last character a number
        if(index == 5 && flag == 0){
            roll2 = 900;
        }
        //roll it is a character
        if(roll2 < nAlphaNum_char_num_distribution[0]*1000){
            for(int i = 0; i < MAX_LOWERCASE_ALPHABETS; i++){
                if(roll <= (nAlphaNum_char_distribution[index][i]*1000)){
                    c = lowercase_alphabets[i];
                    break;
                }
            }
            int isUpper = randomNumGenerator();
            if(isUpper < (char_upper_distribution[0]*1000)){
                return c;
            }
            return toupper(c);
        
        //roll it is a number
        } else {
            for(int i = 0; i < MAX_NUMBERS; i++){
                if(roll <= (nAlphaNum_num_distribution[index][i]*1000)){
                    c = numbers[i];
                    break;
                }
            }
            return c;
        }
    }
    return toupper(c);
}

void generate_pass(char charCombination[][MAX_COMBINATION_PER_CHAR], int numGuessPerWord, int** numGuessRemaining){
    char guess[SMART_GUESS_WORD_LEN+1];
    bzero(guess, SMART_GUESS_WORD_LEN+1);
    for(int i = 0; i < strlen(charCombination[5]); i++){
        for(int j = 0; j < strlen(charCombination[4]); j++){
            for(int k = 0; k < strlen(charCombination[3]); k++){
                for(int l = 0; l < strlen(charCombination[2]); l++){
                    for(int m = 0; m < strlen(charCombination[1]); m++){
                        for(int n = 0; n < strlen(charCombination[0]); n++){
                            guess[0] = charCombination[0][n];
                            guess[1] = charCombination[1][m];
                            guess[2] = charCombination[2][l];
                            guess[3] = charCombination[3][k];
                            guess[4] = charCombination[4][j];
                            guess[5] = charCombination[5][i];
                            printf("%s\n", guess);
                            (**numGuessRemaining) --;
                            numGuessPerWord --;
                            if(numGuessPerWord == 0){
                                return;
                            }
                            if((**numGuessRemaining) == 0){
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

void generate_suffix_and_password(char* suffix, int suffix_length, char* prefix, int* numGuessRemaining){
    char number[2];
    bzero(number, 2);
    sprintf(number, "%d", randomNumGenerator()); 
    strcpy(suffix, number);
    if(suffix_length > 1){
        for(int i = 0; i < suffix_length - 1; i++){
            bzero(number, 2);
            sprintf(number, "%d", randomNumGenerator()); 
            strcat(suffix, number);
        }
    }
    printf("%s%s\n", prefix, suffix);
    (*numGuessRemaining)--;
    return;
}

//generate random number between 0 - 9 
//source: https://www.tutorialspoint.com/c_standard_library/c_function_rand.htm
int randomNumGenerator(){
    //selective spits out a int between 0-9 based 
    //on the distribution of numbers in common_passwords.txt
    int random = rand() % 1000;
/*     if(random < 32){
        return 1;
    }else if (random < 47){
        return 2;
    }else if (random < 57){
        return 3;
    }else if (random < 65){
        return 4;
    }else if (random < 73){
        return 5;
    }else if (random < 80){
        return 6;
    }else if (random < 87){
        return 7;
    }else if (random < 92){
        return 8;
    }else{
        return 9;
    } */

    return random;
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
