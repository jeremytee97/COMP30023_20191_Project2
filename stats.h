#ifndef STATS_H
#define STATS_H

/* Stats_H contains all statistics derived from using the stats_common_password.ipynb (python)*/

//Cummulative distribution for alphabet guesses, for each index, for each lower case character
//6 character and for each character 26 lowercase alphabets (a..z)
const float alpha_char_distribution[SMART_GUESS_WORD_LEN][MAX_LOWERCASE_ALPHABETS] 
= {{0.05, 0.13, 0.22, 0.27, 0.29, 0.33, 0.38, 0.42, 0.43, 0.46, 0.49, 0.53, 0.60, 0.63, 0.64, 0.70, 0.71, 0.76, 0.87, 0.92, 0.93, 0.95, 0.97, 0.98, 0.99, 1}
  ,{0.19, 0.20, 0.21, 0.22, 0.33, 0.34, 0.35, 0.40, 0.51, 0.52, 0.53, 0.57, 0.59, 0.61, 0.77, 0.78, 0.79, 0.86, 0.87, 0.89, 0.95, 0.96, 0.97, 0.98, 0.99, 1}
  ,{0.09, 0.12, 0.16, 0.19, 0.26, 0.27, 0.31, 0.32, 0.37, 0.38, 0.39, 0.47, 0.51, 0.61, 0.67, 0.69, 0.70, 0.79, 0.85, 0.90, 0.94, 0.95, 0.97, 0.98, 0.99, 1}
  ,{0.07, 0.09, 0.13, 0.18, 0.28, 0.30, 0.34, 0.37, 0.44, 0.45, 0.49, 0.54, 0.58, 0.66, 0.70, 0.73, 0.74, 0.79, 0.84, 0.92, 0.94, 0.96, 0.97, 0.98, 0.99, 1}
  ,{0.09, 0.11, 0.14, 0.16, 0.32, 0.33, 0.35, 0.39, 0.47, 0.48, 0.51, 0.56, 0.59, 0.65, 0.73, 0.75, 0.76, 0.81, 0.86, 0.91 ,0.93, 0.94, 0.95, 0.96, 0.99, 1}
  ,{0.09, 0.10, 0.12, 0.15, 0.29, 0.30, 0.32, 0.34, 0.40, 0.41, 0.42, 0.46, 0.48, 0.58, 0.65, 0.66, 0.67, 0.78, 0.85, 0.90, 0.92, 0.93, 0.94, 0.95, 0.99, 1}
};

//Cummulative distribution for alphabet guesses, for lowercase(99%) and uppercase(1%) distribution
const float char_upper_distribution[] = {0.99, 1};

//Cummulative distribution for alphanumeric guesses, for alphabets(90%) and number(10%) distribution
const float alphaNum_char_num_distribution[] = {0.90, 1};

//Cummulative distribution for alphanumeric lowercase character distribution for each index
//6 character and for each character 26 lowercase alphabets (a..z)
const float alphaNum_char_distribution[SMART_GUESS_WORD_LEN][MAX_LOWERCASE_ALPHABETS]
={{0.05, 0.13, 0.22, 0.27, 0.29, 0.33, 0.38, 0.42, 0.43, 0.47, 0.49, 0.53, 0.60, 0.63, 0.64, 0.705, 0.712, 0.76, 0.87, 0.925, 0.93, 0.95, 0.978, 0.98, 0.99, 1}
 ,{0.19, 0.198, 0.21, 0.217, 0.34, 0.342, 0.345, 0.4, 0.514, 0.516, 0.522, 0.57, 0.59, 0.61, 0.77, 0.787, 0.79, 0.86, 0.87, 0.89, 0.96, 0.97,0.98, 0.987, 0.99, 1}
 ,{0.09, 0.12, 0.16, 0.19, 0.26, 0.27, 0.31, 0.32, 0.379, 0.383, 0.394, 0.47, 0.51, 0.61, 0.67, 0.695, 0.698, 0.79, 0.85, 0.90, 0.94, 0.95, 0.97, 0.98, 0.99, 1}
 ,{0.07, 0.09, 0.13, 0.18, 0.28, 0.30, 0.34, 0.37, 0.442, 0.447, 0.486, 0.544, 0.58, 0.66, 0.70, 0.73, 0.735, 0.79, 0.84, 0.92, 0.94, 0.96, 0.97, 0.974, 0.99, 1}
 ,{0.09, 0.11, 0.13, 0.16, 0.32, 0.33, 0.35, 0.39, 0.477, 0.482, 0.51, 0.56, 0.59, 0.65, 0.73, 0.749, 0.751, 0.81, 0.86, 0.91, 0.936, 0.94, 0.95, 0.953, 0.995, 1}
 ,{0.09, 0.10, 0.12, 0.15, 0.29, 0.30, 0.32, 0.34, 0.40, 0.41, 0.42, 0.46, 0.48, 0.58, 0.65, 0.665, 0.667, 0.78, 0.85, 0.90, 0.92, 0.93, 0.94, 0.95, 0.995, 1}
 };

//Cummulative distribution for alphanumeric numeric character distribution for each index
//6 character and for each character 10 numeric character (0..9)
const float alphaNum_num_distribution[SMART_GUESS_WORD_LEN][MAX_NUMBERS]
= {{0.05, 0.48, 0.59, 0.66, 0.74, 0.82, 0.87, 0.93, 0.96, 1}
  ,{0.13, 0.26, 0.43, 0.50, 0.57, 0.65, 0.72, 0.77, 0.84, 1}
  ,{0.11, 0.23, 0.41, 0.52, 0.60, 0.696, 0.80, 0.88, 0.94, 1}
  ,{0.10, 0.26, 0.36, 0.46, 0.57, 0.65, 0.73, 0.82, 0.90, 1}
  ,{0.08, 0.26, 0.46, 0.56, 0.64, 0.77, 0.85, 0.90, 0.95, 1}
  ,{0.06, 0.51, 0.60, 0.69, 0.76, 0.80, 0.86, 0.91, 0.95, 1}
  };

//Cummulative numeric distribution of numbers
// 0..9
const float number_distribution[MAX_NUMBERS] = {0.06, 0.37, 0.50, 0.59, 0.67, 0.75, 0.82, 0.89, 0.93, 1};

#endif
