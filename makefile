##############################################################
#
#                   DO NOT EDIT THIS FILE!
#
##############################################################
# If the tool is built out of the kit, PIN_ROOT must be specified in the make invocation and point to the kit root.
ifeq ($(shell uname), Darwin)
	PIN_ROOT=../pin-2.14-71313-clang.5.1-mac
else
	PIN_ROOT=../pin-2.14-71313-gcc.4.4.7-linux
endif
ifdef PIN_ROOT
CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
else
CONFIG_ROOT := ../Config
endif
include $(CONFIG_ROOT)/makefile.config
include makefile.rules
#include $(TOOLS_ROOT)/Config/makefile.default.rules

##############################################################
#
#                   DO NOT EDIT THIS FILE!
#
##############################################################
