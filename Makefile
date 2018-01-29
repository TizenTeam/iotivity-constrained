port?=linux

.PHONY: default help README

default: all
	sync

%: port/${port}
	make -C $< $@

help: README.rst
	cat $<
	@echo "make all : to build port=${port}"

.PHONY: help
