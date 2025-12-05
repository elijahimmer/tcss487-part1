CLASS_PATH := "class"
C_EXEC := "sha3"
KEY_FILE := "id_ed15343"
JAVA_PARAMETERS := ("-cp " + CLASS_PATH)
RUN_JAVA_CMD := ("java " + JAVA_PARAMETERS + " Main")
ENCRYPT_TEST_FILE := "README.md"

alias jr := java-run
alias jc := java-compile

java-run *ARGS: java-compile
    {{RUN_JAVA_CMD}} {{ARGS}}

java-compile:
    javac -d {{CLASS_PATH}} Main.java SHA3SHAKE.java Edwards.java

c-compile:
    gcc -o {{C_EXEC}} main.c sha3.c

c-run *ARGS:
    ./{{C_EXEC}} {{ARGS}}

test: java-compile c-compile
    @just test-sha
    @just test-shake-encrypt

test-sha SEC FILE:
    ./{{C_EXEC}} sha {{SEC}} {{FILE}} > {{FILE}}.sha
    {{RUN_JAVA_CMD}} sha3 {{SEC}} {{FILE}} | diff {{FILE}}.sha -
    rm {{FILE}}.sha

test-shake-encrypt SEC SEED FILE:
    {{RUN_JAVA_CMD}} shake-encrypt {{SEC}} {{SEED}} {{FILE}} > {{FILE}}.bin
    {{RUN_JAVA_CMD}} shake-encrypt {{SEC}} {{SEED}} {{FILE}}.bin | diff {{FILE}} -
    rm {{FILE}}.bin

test-ec-encrypt:
    {{RUN_JAVA_CMD}} ec-keygen "$(hexdump -vn16 -e'4/4 "%08X" 1 "\n"' /dev/urandom)" {{KEY_FILE}}
    {{RUN_JAVA_CMD}} ec-encrypt {{KEY_FILE}} {{ENCRYPT_TEST_FILE}}
    {{RUN_JAVA_CMD}} ec-decrypt {{KEY_FILE}} {{ENCRYPT_TEST_FILE}}

    rm {{KEY_FILE}} {{KEY_FILE}}.pub


# java -cp {{CLASS_PATH}} Main ec-encrypt {{KEY_FILE}} {{FILE}} > {{FILE}}.bin
# java -cp {{CLASS_PATH}} Main ec-encrypt {{KEY_FILE}} {{FILE}}.bin | diff {{FILE}} -
# rm {{FILE}}.bin



