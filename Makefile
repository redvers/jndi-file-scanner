all:
	corral fetch
	corral run -- ponyc
debug:
	corral fetch
	corral run -- ponyc -d .

clean:
	rm -rf _corral _repos lock.json
