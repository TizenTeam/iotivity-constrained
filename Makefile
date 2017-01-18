port?=linux

.PHONY: default help README

default: help

help: README
	cat $<
	@echo "make all : to build port=${port}"

port/${port}: deps/tinycbor/.gitignore
	ls $@

deps/tinycbor/.gitignore:
	git submodule init
	git submodule sync
	git submodule update
	ls $@

%: port/${port}
	${MAKE} -C $< $@
