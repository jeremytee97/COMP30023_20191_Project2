# teej1_comp30023_2019_project-2


### 1. Statistics for smart guess generation based on common_password.txt and classes hashed passwords:

--------------

#### General overview of the distribution of words
* 82 % are alphabets 
* 11 % are alphanumeric
* 5 % are numbers
--------------

#### Character distribution of passwords
* Passwords comprises of 70 different character
* 99% of passwords dont contain special characters
* 85% of passwords contain either 0 or 1 numbers
* 99% of passwords do not contain uppercase


#### Interesting distribution
* only 2% of words contain consecutive character
* numbers character probability sorted in descending order - 1,2,0,9,3,4,5,6,7,8
* 99% of passwords do not contain uppercase


Password will be generated based on:
6 character, no uppercase, no special characters, either 0 or 1 numbers


## To run this program, 


1.  run "make clean" - to remove all binary files and executables
2.  run "make" - to create executable files
3.  run "./crack NUMBEROFGUESSTOGENERATE" / "./crack GUESSFILE HASHFILE"
