#!/usr/bin/python

import sys, getopt, base64
from passlib.hash import pbkdf2_sha256

count = 0

def transform(myHash):
   decode = base64.b64decode(myHash.replace(".", "+") + '==')
   return decode
   
def decodeHash(wordList,myHash):
   # Using readlines()
   global count 
   file1 = open(wordList, 'r') 
   Lines = file1.readlines() 
   # Strips the newline character 
   myHash = myHash.split("$")
   iteration = myHash[2]
   salt = transform(myHash[3])
   passEncoded = myHash[4]
   for line in Lines:       
      resultHash = pbkdf2_sha256.using(rounds=iteration, salt=salt).hash(line.strip())
      resultHashSplit = resultHash.split("$")
      if passEncoded == resultHashSplit[4]:
         print("***** Password Finded:\n{} : {}".format(line.strip(),resultHash))
         count = count+1 


# TODO decodeHashFile
def decodeHashFile(wordList,myHashFile):
   file1 = open(myHashFile, 'r') 
   Lines = file1.readlines() 
   # Strips the newline character 
   for line in Lines:
      decodeHash(wordList,line.strip())  

def main(argv):
   wordList = ''
   myHash   = ''
   hashFile = ''
   try:
      opts, args = getopt.getopt(sys.argv[1:],'h:w:H:f',['help','word-list=','hash=','file='])
   except getopt.GetoptError:
      print 'typo3Pbkdf2_decript.py -w <word-list> [--word-list=] -H <hash> [--hash=] -f <hash-file> [--file=]'
      print 'Example 1: typo3Pbkdf2_decript.py -w wordList.txt -H $pbkdf2-sha256$25000$kplrxs.boglp6f5d935.qa$jfgkrlnvhy9bhanolzlfgqln9cng3l39ggcc2jzlgpo'
      print 'Example 2: typo3Pbkdf2_decript.py -w wordList.txt -f hashFile.txt'
      print 'Example 3: typo3Pbkdf2_decript.py --word-list=wordList.txt --hash=$pbkdf2-sha256$25000$kplrxs.boglp6f5d935.qa$jfgkrlnvhy9bhanolzlfgqln9cng3l39ggcc2jzlgpo'
      print 'Example 4: typo3Pbkdf2_decript.py --word-list=wordList.txt --file=hashFile.txt'
      
      sys.exit(2)
   for opt, arg in opts:
      if opt in ('-h','--help'):
         print 'typo3Pbkdf2_decript.py -w <word-list> [--word-list=]'
         sys.exit()
      elif opt in ('-w', '--word-list'):
         wordList = arg
      elif opt in ('-H', '--hash'):
         myHash = arg
      elif opt in ('-f', '--file'):
         hashFile = arg
   
   print ''
   print ''
   print '++++++++++++++++++++++++++++++++++++++++++'
   print ''
   print 'Word List File      [ ', wordList,' ]' 
   if myHash:
      print 'Hash                [ ', myHash,' ]'
      decodeHash(wordList,myHash)
   if hashFile:
      print 'Hash File           [ ', hashFile,' ]'
      decodeHashFile(wordList,hashFile)
   print 'Decripted Hash      [ '+str(count)+ ' ]'
   print ''
   print '++++++++++++++++++++++++++++++++++++++++++'

if __name__ == "__main__":
   main(sys.argv[1:])
