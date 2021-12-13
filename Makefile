all:
	corral fetch
	corral run -- ponyc
debug:
	corral fetch
	corral run -- ponyc -d .
