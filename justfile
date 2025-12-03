CLASS_PATH := "class"
C_EXEC := "sha3"

c-compile:
    gcc -o {{C_EXEC}} main.c sha3.c

c-run *ARGS:
    ./{{C_EXEC}} {{ARGS}}

java-compile:
    javac -d {{CLASS_PATH}} Main.java SHA3SHAKE.java

java-run *ARGS: java-compile
    java -cp {{CLASS_PATH}} Main {{ARGS}}

test: java-compile c-compile
    @just test-sha
    @just test-shake-encrypt

test-sha SEC FILE:
    ./{{C_EXEC}} sha {{SEC}} {{FILE}} > {{FILE}}.sha
    java -cp {{CLASS_PATH}} Main sha3 {{SEC}} {{FILE}} | diff {{FILE}}.sha -
    rm {{FILE}}.sha

test-shake-encrypt SEC SEED FILE:
    java -cp {{CLASS_PATH}} Main shake-encrypt {{SEC}} {{SEED}} {{FILE}} > {{FILE}}.bin
    java -cp {{CLASS_PATH}} Main shake-encrypt {{SEC}} {{SEED}} {{FILE}}.bin | diff {{FILE}} -
    rm {{FILE}}.bin




