.PHONY: proof

proof: deps
	make -C bin
	stack build
	stack exec proof

deps:
	mkdir -p deps
	git clone -b x86-initialized 'https://github.com/GaloisInc/saw-script' deps/saw-script
	cd deps/saw-script; git submodule update --init; cd deps/abcBridge; git submodule update --init
