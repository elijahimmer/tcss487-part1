CLASS_PATH := "class"
C_EXEC := "sha3"
KEY_FILE := "id_ed15343"
JAVA_PARAMETERS := ("-cp " + CLASS_PATH + " -enableassertions")
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
    @just test-sha 256 README.md
    @just test-shake 256
    @just test-shake-encrypt 256 {{PASSWORD}} README.md
    @just test-ec-encrypt
    @just test-ec-sign

test-sha SEC FILE:
    ./{{C_EXEC}} sha {{SEC}} {{FILE}} > {{FILE}}.sha
    {{RUN_JAVA_CMD}} sha3 {{SEC}} {{FILE}} | diff {{FILE}}.sha -
    rm {{FILE}}.sha

test-shake SEC:
    ./{{C_EXEC}} shake {{SEC}} 256 password > test.bin
    {{RUN_JAVA_CMD}} shake-random {{SEC}} password 256 | diff test.bin -
    rm test.bin

test-shake-encrypt SEC SEED FILE:
    {{RUN_JAVA_CMD}} shake-encrypt {{SEC}} {{SEED}} {{FILE}} > {{FILE}}.bin
    {{RUN_JAVA_CMD}} shake-encrypt {{SEC}} {{SEED}} {{FILE}}.bin | diff {{FILE}} -
    rm {{FILE}}.bin

PASSWORD := `hexdump -vn16 -e'4/4 "%08X" 1 "\n"' /dev/urandom`

test-ec-generate-key:
    {{RUN_JAVA_CMD}} ec-keygen "{{PASSWORD}}" {{KEY_FILE}}

test-ec-encrypt: test-ec-generate-key
    {{RUN_JAVA_CMD}} ec-encrypt {{KEY_FILE}} {{ENCRYPT_TEST_FILE}}
    {{RUN_JAVA_CMD}} ec-decrypt {{KEY_FILE}} {{ENCRYPT_TEST_FILE}}.bin | diff {{ENCRYPT_TEST_FILE}} -
    rm {{ENCRYPT_TEST_FILE}}.bin {{KEY_FILE}} {{KEY_FILE}}.pub

test-ec-sign: test-ec-generate-key
    {{RUN_JAVA_CMD}} ec-sign "{{PASSWORD}}" {{ENCRYPT_TEST_FILE}} > {{ENCRYPT_TEST_FILE}}.sig
    echo "VERIFIED" > test
    {{RUN_JAVA_CMD}} ec-verify {{KEY_FILE}}.pub {{ENCRYPT_TEST_FILE}}.sig {{ENCRYPT_TEST_FILE}} | diff test -
    rm {{ENCRYPT_TEST_FILE}}.sig {{KEY_FILE}} {{KEY_FILE}}.pub test


