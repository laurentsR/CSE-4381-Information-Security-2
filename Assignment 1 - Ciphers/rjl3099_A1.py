# Ryan Laurents - ID: 1000763099
# CSE 4381 - Info Sec 2
# Assignment 1

# NOTE TO GRADER: Q2/Q3 Uses a .txt file of the Mark Twain story. If you want to run the file, you will
#                 need to replace the below variable (fileName) with the .txt file name. If you run the
#                 code without doing so it will error.
#                 Methodology is explained for each question in a comment. Most answers are printed.
fileName = "markTwain.txt"

import codecs
import operator
from string import ascii_letters


# ~~~~~~~~~~~~~~~~~~~~~~
# ~~    Question 1    ~~
# ~~~~~~~~~~~~~~~~~~~~~~
# Q: Show how to do a rot-13 for the message: "Security is often important"
# Method:
#    Answer found from stack overflow link provided with assignment.
#    https://stackoverflow.com/questions/3269686/short-rot13-function-python
#    Import the codecs library and use the encode function, specify rot13.

q1Ans = codecs.encode("Security is often important", "rot_13")
print("Q1 Answer: " + q1Ans)

# ~~~~~~~~~~~~~~~~~~~~~~
# ~~    Question 2    ~~
# ~~~~~~~~~~~~~~~~~~~~~~
# Q: Show how to do a simple (letter by letter) substitution cipher, please encrypt
#    the Mark Twain story. (You will need to create a key, you can do this by hand or
#    use a simple software implementation.)
# Method:
#    Create my own key based on randomly cutting 3 characters at a time from the
#    set and pasting them into the key. When all chanracters are gone, the key is
#    ready. Keep an extra copy of the set to use for later.
#    Inspiration taken from https://codereview.stackexchange.com/questions/166452/substitution-cipher-in-python-3

# Create a key of every character on my keyboard. Use the \ to escape the ' from closing the string.
characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ 1234567890!@#$%^&*()-=_+[]{}\|\'";:/?.>,<`~'
key = 'xyzUV W_+[def>,<wAB0!@\|\'/?.ijkvCDhlmbcgQRS#$%pqrLMNZ12stu]{}TXYP34O56JK7-="noEaFG^&*();HI89:`~'
translation = str.maketrans(characters, key)

# Bring in the text needed to be ciphered.
with open(fileName, 'r') as file:
    data = file.read().replace('\n', '')

# Run the data through the cipher
q2Ans = data.translate(translation)
print("Q2 Answer: " + q2Ans)

# ~~~~~~~~~~~~~~~~~~~~~~
# ~~    Question 3    ~~
# ~~~~~~~~~~~~~~~~~~~~~~
# Q: One problem with #2, is that letter frequencies may make cracking easy.
#    For the original (plaintext) show the letter frequencies.
# Method:
#    I'll go through the data character by character and check if it is in a master
#    dictionary. If not, add it with the key = 1. If it is, increment the key by one.
#    Make sure to catch \n characters. Cycle through characters until finished.

frequencies = {}
file = open(fileName, 'r')

while 1:
    char = file.read(1)
    if not char:
        break
    if char == '\n':
        continue
    if char not in frequencies:
        frequencies[char] = 1
    else:
        frequencies[char] += 1

# Sort the frequencies in descending order before printing
q3Ans = dict(sorted(frequencies.items(), key = operator.itemgetter(1), reverse = True))
print("Q3 Answer: ")
print(q3Ans)

# ~~~~~~~~~~~~~~~~~~~~~~
# ~~    Question 4    ~~
# ~~~~~~~~~~~~~~~~~~~~~~
# Q: One possible solution to #3 is to use homophonic substitution. Show how
#    that can be done.
# Method:
#    Homophonic Substitution is where a single character can be encrypted to several other characters.
#    I'll use a small example where the input characters are only two letters.
#    For each of these letters, the cipher will access a dictionary. The key
#    will be a list with three values. True/False, 1st Letter, 2nd Letter.
#    On each access, the True/False flips and you will access the 1st/2nd letter
#    based on the TF value.

input = 'ABABABAB'
q4Key = {}
q4Key['A'] = [True, '1', '3']
q4Key['B'] = [True, '2', '4']

output = ''
for char in input:
    if char not in q4Key:
        print("Character not found in key. Q4")
    if q4Key[char][0] == True:
        output = output + q4Key[char][1]
        q4Key[char][0] = False
    else:
        output = output + q4Key[char][2]
        q4Key[char][0] = True
print('Q4 Input = ' + input)
print('Q4 Output = ' + output)

# ~~~~~~~~~~~~~~~~~~~~~~
# ~~    Question 5    ~~
# ~~~~~~~~~~~~~~~~~~~~~~
# Q: How would you use part 3 (above) to crack a cipher?
# Method:
#    There are several different things you could do to crack a substitution cipher.
#    For example, the most common letters in the English Language are:
#    E, A, R, I, O, T, N, S
#    The most common letters in our sample text were:
#    E, T, A, O, N, S, I, R
#    As you can see: same letters, different order.
#    You could use the english language frequencies as a guide for trial and error.
#    If you take the above letters and map them to the most common characters in the
#    encrypted text (minus the first one for space), you could try various combinations
#    (max of 64) until you got some readable words out of it. You would be able to find
#    common stopwords such as "to", "so", "on", "an" etc. If you get a combination where
#    all of the decrypted text is readable, it is likely that those are correct.
#    Rinse and repeat. There are other methods commonly used that only work for ciphers
#    that DON'T encrypt the spaces and apostrophes. Such as searching for single letter
#    words and assuming they are A or I.

print("Q5 Answer: Please see comment from line 112-127")
