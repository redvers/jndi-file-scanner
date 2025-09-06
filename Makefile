all:
	corral fetch
	corral run -- ponyc

static:
	corral fetch
	corral run -- ponyc --static

debug:
	corral fetch
	corral run -- ponyc -d .

clean:
	rm -rf _corral _repos lock.json
