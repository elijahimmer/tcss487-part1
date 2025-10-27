set -euxo pipefail

CLASS_PATH=class
C_EXEC=sha3
TEST_RESULT=test.sha3

javac -d $CLASS_PATH Driver.java SHA3SHAKE.java
gcc -o $C_EXEC main.c sha3.c

./sha3 $@ > $TEST_RESULT
java -cp $CLASS_PATH Driver $@ | diff $TEST_RESULT -
