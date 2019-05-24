
#ifndef CRACK_H
#define CRACK_H

#define MAX_KEYWORDS 95
#define MAX_ALPHABETS 52
#define MAX_LOWERCASE_ALPHABETS 26
#define MAX_NUMBERS 10

#define PWD4_GUESS_LENGTH 4
#define PWD6_GUESS_LENGTH 6

#define SMART_GUESS_WORD_LEN 6
#define MAX_COMBINATION_PER_CHAR 6
#define NUM_PWD4SHA256 10
#define NUM_PWD6SHA256 20

#define PWD4_FILENAME "pwd4sha256"
#define PWD6_FILENAME "pwd6sha256"
#define COMMON_PASS_FILENAME "common_passwords.txt"

//FOR SMART GUESS
#define FIRST_CHAR 0
#define SECOND_CHAR 1
#define THIRD_CHAR 2
#define FOURTH_CHAR 3
#define FIFTH_CHAR 4
#define SIXTH_CHAR 5
#define ALPHA_PASS 0
#define ALPHANUMERIC_PASS 1
#define NUMERIC_PASS 2
#define PERCENTAGE_ALPHABETS_PASSWORD 0.88
#define PERCENTAGE_ALPHANUMERIC_PASSWORD 0.11
               
const float nAlpha_char_distribution[SMART_GUESS_WORD_LEN][MAX_LOWERCASE_ALPHABETS] 
= {{0.05, 0.13, 0.22, 0.27, 0.29, 0.33, 0.38, 0.42, 0.43, 0.46, 0.49, 0.53, 0.60, 0.63, 0.64, 0.70, 0.71, 0.76, 0.87, 0.92, 0.93, 0.95, 0.97, 0.98, 0.99, 1}
  ,{0.19, 0.20, 0.21, 0.22, 0.33, 0.34, 0.35, 0.40, 0.51, 0.52, 0.53, 0.57, 0.59, 0.61, 0.77, 0.78, 0.79, 0.86, 0.87, 0.89, 0.95, 0.96, 0.97, 0.98, 0.99, 1}
  ,{0.09, 0.12, 0.16, 0.19, 0.26, 0.27, 0.31, 0.32, 0.37, 0.38, 0.39, 0.47, 0.51, 0.61, 0.67, 0.69, 0.70, 0.79, 0.85, 0.90, 0.94, 0.95, 0.97, 0.98, 0.99, 1}
  ,{0.07, 0.09, 0.13, 0.18, 0.28, 0.30, 0.34, 0.37, 0.44, 0.45, 0.49, 0.54, 0.58, 0.66, 0.70, 0.73, 0.74, 0.79, 0.84, 0.92, 0.94, 0.96, 0.97, 0.98, 0.99, 1}
  ,{0.09, 0.11, 0.14, 0.16, 0.32, 0.33, 0.35, 0.39, 0.47, 0.48, 0.51, 0.56, 0.59, 0.65, 0.73, 0.75, 0.76, 0.81, 0.86, 0.91 ,0.93, 0.94, 0.95, 0.96, 0.99, 1}
  ,{0.09, 0.10, 0.12, 0.15, 0.29, 0.30, 0.32, 0.34, 0.40, 0.41, 0.42, 0.46, 0.48, 0.58, 0.65, 0.66, 0.67, 0.78, 0.85, 0.90, 0.92, 0.93, 0.94, 0.95, 0.99, 1}
};
const float char_upper_distribution[] = {0.99, 1};

const float nAlphaNum_char_num_distribution[] = {0.90, 1};

const float nAlphaNum_char_distribution[SMART_GUESS_WORD_LEN][MAX_LOWERCASE_ALPHABETS]
={{0.05, 0.13, 0.22, 0.27, 0.29, 0.33, 0.38, 0.42, 0.43, 0.47, 0.49, 0.53, 0.60, 0.63, 0.64, 0.705, 0.712, 0.76, 0.87, 0.925, 0.93, 0.95, 0.978, 0.98, 0.99, 1}
 ,{0.19, 0.198, 0.21, 0.217, 0.34, 0.342, 0.345, 0.4, 0.514, 0.516, 0.522, 0.57, 0.59, 0.61, 0.77, 0.787, 0.79, 0.86, 0.87, 0.89, 0.96, 0.97,0.98, 0.987, 0.99, 1}
 ,{0.09, 0.12, 0.16, 0.19, 0.26, 0.27, 0.31, 0.32, 0.379, 0.383, 0.394, 0.47, 0.51, 0.61, 0.67, 0.695, 0.698, 0.79, 0.85, 0.90, 0.94, 0.95, 0.97, 0.98, 0.99, 1}
 ,{0.07, 0.09, 0.13, 0.18, 0.28, 0.30, 0.34, 0.37, 0.442, 0.447, 0.486, 0.544, 0.58, 0.66, 0.70, 0.73, 0.735, 0.79, 0.84, 0.92, 0.94, 0.96, 0.97, 0.974, 0.99, 1}
 ,{0.09, 0.11, 0.13, 0.16, 0.32, 0.33, 0.35, 0.39, 0.477, 0.482, 0.51, 0.56, 0.59, 0.65, 0.73, 0.749, 0.751, 0.81, 0.86, 0.91, 0.936, 0.94, 0.95, 0.953, 0.995, 1}
 ,{0.09, 0.10, 0.12, 0.15, 0.29, 0.30, 0.32, 0.34, 0.40, 0.41, 0.42, 0.46, 0.48, 0.58, 0.65, 0.665, 0.667, 0.78, 0.85, 0.90, 0.92, 0.93, 0.94, 0.95, 0.995, 1}
 };

const float nAlphaNum_num_distribution[SMART_GUESS_WORD_LEN][MAX_NUMBERS]
= {{0.05, 0.48, 0.59, 0.66, 0.74, 0.82, 0.87, 0.93, 0.96, 1}
  ,{0.13, 0.26, 0.43, 0.50, 0.57, 0.65, 0.72, 0.77, 0.84, 1}
  ,{0.11, 0.23, 0.41, 0.52, 0.60, 0.696, 0.80, 0.88, 0.94, 1}
  ,{0.10, 0.26, 0.36, 0.46, 0.57, 0.65, 0.73, 0.82, 0.90, 1}
  ,{0.08, 0.26, 0.46, 0.56, 0.64, 0.77, 0.85, 0.90, 0.95, 1}
  ,{0.06, 0.51, 0.60, 0.69, 0.76, 0.80, 0.86, 0.91, 0.95, 1}
  };

/*Function declaration*/
int compareHashes(BYTE** file, BYTE* guess, int num_hashes, int guess_length);

void compareAllGuesses(char* guess, BYTE** file, int num_hashes);

void generate_password(int numOfGuesses);

void generate_similar_words(int* numGuessRemaining);

void generate_pass_buffer(char charCombination[][MAX_COMBINATION_PER_CHAR], char* word, int type);

void generate_pass(char charCombination[][MAX_COMBINATION_PER_CHAR], int numGuessPerWord, int** numGuessRemaining);

int dictionaryAttack(int numGuessRequired);

void calculate_distribution(int numGuessRemaining, int* nAlpha, int* nAlphaNum, int* nNumbers);

char characterGenerator(int roll, int index, int type, int flag);

void generate_word(int numGuessRemaining, int type);

char* reverseWord(char* suffix);

float max(float x, float y);

int randomNumGenerator();

void generate_suffix_and_password(char* suffix, int suffix_length, char* prefix, int* numGuessRemaining);

void generateFourCharPass(int maxlen, BYTE** file, int numberOfHash);

void generateSixCharPass(int maxlen, BYTE** file, int numberOfHash);

int readHashFile(char* filename, BYTE*** buffer);

BYTE* hashGuess(BYTE* guess, int guess_length);

#endif // SHA256_H
