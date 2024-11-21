#######################################################
#### Makefile for ChipWhisperer simpleserial-mlkem ####
#######################################################

# On command line:
#
# make all = Make software.
#
# make clean = Clean out built project files.
#
# make coff = Convert ELF to AVR COFF.
#
# make extcoff = Convert ELF to AVR Extended COFF.
#
# make program = Download the hex file to the device, using avrdude.
#                Please customize the avrdude settings below first!
#
# make debug = Start either simulavr or avarice as specified for debugging,
#              with avr-gdb or avr-insight as the front end for debugging.
#
# make filename.s = Just compile filename.c into the assembler code only.
#
# make filename.i = Create a preprocessed source file for use in submitting
#                   bug reports to the GCC project.
#
# To rebuild project do "make clean" then "make all".
#----------------------------------------------------------------------------------------
CWPATH = /home/kali/chipwhisperer

# Target file name (without extension).
# This is the base name of the compiled .hex file.
TARGET = simpleserial-kyber

# List C source files here.
# Header files (.h) are automatically pulled in.
SRC += simpleserial-kyber.c

# Extra option to set Kyber_K in {2, 3, 4}
K ?= 2
EXTRA_OPTS = KYBER_K=$(K)
CFLAGS += -D$(EXTRA_OPTS) 

# Extra option to set SHUFFLED in {0, 1}
SHUFFLED ?= 0

# ifeq ($(CRYPTO_OPTIONS),)
# CRYPTO_OPTIONS = AES128C
# endif

# Add simpleserial project to build
# FIRMWAREPATH = $(CWPATH)/hardware/victims/firmware
FIRMWAREPATH = ..

# include $(FIRMWAREPATH)/simpleserial/Makefile.simpleserial
include ../simpleserial/Makefile.simpleserial
include ../Makefile.inc