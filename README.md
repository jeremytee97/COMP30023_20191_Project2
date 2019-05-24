# teej1_comp30023_2019_project-2


### 1. Statistics for smart guess generation based on common_password.txt and classes hashed passwords:

> Statistics are calculated using Stats_common_password.ipynb (python jupyter notebook)
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
* In most cases, uppercase are in the first few characters

Flow of the program for 1 argument (Generate passwords)
1. Try dictionary attack, spit out words from common_passwords.txt
   - 3 cases: 
        - word length = 6 (nice, just print out)
        - word length > 6 (slice word so word length = 6 and print)
        - word length < 6 (digit padding, based on distribution of numbers)

2. Smart generation of password will be based on:
   - 6 character, split into alphabets (82%), alphanumeric(11%) and numeric passwords (5%)
   - How it works:
        - statisics of each character for each index is calculated
        - based on the statistics, it is randomly generated.


## To run this program, 


1.  run "make clean" - to remove all binary files and executables
2.  run "make" - to create executable files
3.  run "./crack NUMBEROFGUESSTOGENERATE" OR "./crack GUESSFILE HASHFILE"
