# jndi-file-scanner

Command-line tool to scan .zip/.ear/.war/.jar files recursively for files associated with the log4j vulnerability.

## Status

jndi-file-scanner is "in-flight".  As we are following where the world takes us this tool will change over time.

## Installation

Dependencies:
* libzip [https://libzip.org](https://libzip.org/)
* pcre2 [https://www.pcre.org](https://www.pcre.org/)
* ponyc	[https://github.com/ponylang/ponyc/blob/main/INSTALL.md](https://github.com/ponylang/ponyc/blob/main/INSTALL.md)
* corral [https://github.com/ponylang/corral](https://github.com/ponylang/corral)

Get libzip however your distribution packages it.
The Pony Project recommend using ponyup to install ponyc and corral.  Instructions on the website.

### How to build

For example, on Ubuntu:

```shell
sudo apt install curl build-essential git cmake clang libpcre2-dev libzip-dev
*install ponyup*
ponyup default ubuntu18.04
ponyup update ponyc release
ponyup update corral release
git clone https://github.com/redvers/jndi-file-scanner
cd jndi-file-scanner
make
```

If you have any issues, please open one or hit me up on twitter @noidd

I have not used any Linux specific code so it should be able to compile for Windows too. YMMV


## Usage

```quote
usage: jndi-file-scanner [<options>] [<args> ...]

CLI program to help you find vulnerable artifacts

Options:
   -c, --crc=false                     output zipfile crc
   -f, --filename                      File to search
   -h, --help=false
   -s, --sha256=false                  output calculated sha256
   -a, --all=false                     All filenames
   -i, --insensitive=false             Case Insensitive
   -r, --regex=(?i)JndiLookup.class    Custom Regex
```

### Flag detail

* -c  You should probaby use -s (sha256) instead, but this remains as an option in case you are running on a system with low memory.
* -f  Provides the filename of the file you with to scan (supports anything which is really a zip-file).
* -s  Outputs the SHA256 of any file that matches your regex.
* -a  Sets the regex to '.', ie - ALL files.
* -i  Makes your regex case insensitive (prepends (?i) to your regex for you)
* -r  Provides the regex you wish to search for. (Put your regex in single quotes unless you really know what you're doing in shell)™


## Examples

### Simple Example

Find any filenames that contain log4j either in the filename or in their path:

```quote
[nix-shell:~/projects/pony/jndi-file-scanner/testjars]$ for f in forge*jar;do ../jndi-file-scanner -f $f -r 'log4j' -i; done
FOUND -> forge-1.12.2-14.23.5.2854-installer(1).jar -> maven/net/minecraftforge/forge/1.12.2-14.23.5.2854/forge-1.12.2-14.23.5.2854.jar -> log4j2.xml
FOUND -> forge-1.12.2-14.23.5.2854-installer(1).jar -> maven/net/minecraftforge/forge/1.12.2-14.23.5.2854/forge-1.12.2-14.23.5.2854.jar -> log4j2_server.xml
FOUND -> forge-1.12.2-14.23.5.2854-installer.jar -> maven/net/minecraftforge/forge/1.12.2-14.23.5.2854/forge-1.12.2-14.23.5.2854.jar -> log4j2.xml
FOUND -> forge-1.12.2-14.23.5.2854-installer.jar -> maven/net/minecraftforge/forge/1.12.2-14.23.5.2854/forge-1.12.2-14.23.5.2854.jar -> log4j2_server.xml
FOUND -> forge-1.13.2-25.0.108-installer.jar -> maven/net/minecraftforge/forge/1.13.2-25.0.108/forge-1.13.2-25.0.108-universal.jar -> log4j2.xml
FOUND -> forge-1.13.2-25.0.108-installer.jar -> maven/net/minecraftforge/forge/1.13.2-25.0.108/forge-1.13.2-25.0.108-universal.jar -> log4j2_server.xml
FOUND -> forge-1.14.3-27.0.60-installer.jar -> maven/net/minecraftforge/forge/1.14.3-27.0.60/forge-1.14.3-27.0.60-universal.jar -> log4j2.xml
FOUND -> forge-1.14.3-27.0.60-installer.jar -> maven/net/minecraftforge/forge/1.14.3-27.0.60/forge-1.14.3-27.0.60-universal.jar -> log4j2_server.xml
FOUND -> forge-1.14.3-27.0.60-installer.jar -> maven/net/minecraftforge/forge/1.14.3-27.0.60/forge-1.14.3-27.0.60.jar -> log4j2.xml
etc ...
```

#### More complex example

Identify when a specific class has changed over time:

```quote
[nix-shell:~/projects/pony/jndi-file-scanner/testjars]$ for f in forge*jar;do ../jndi-file-scanner -f $f -r 'BackgroundScanHandler.class' -s; done
SHA256:8805ca6d0fa923ce0bd3eccc1394f1cc57642c82ca844cfb043e031c02204292: FOUND -> forge-1.13.2-25.0.108-installer.jar -> maven/net/minecraftforge/forge/1.13.2-25.0.108/forge-1.13.2-25.0.108.jar -> net/minecraftforge/fml/loading/moddiscovery/BackgroundScanHandler.class
SHA256:8805ca6d0fa923ce0bd3eccc1394f1cc57642c82ca844cfb043e031c02204292: FOUND -> forge-1.14.3-27.0.60-installer.jar -> maven/net/minecraftforge/forge/1.14.3-27.0.60/forge-1.14.3-27.0.60.jar -> net/minecraftforge/fml/loading/moddiscovery/BackgroundScanHandler.class
SHA256:8805ca6d0fa923ce0bd3eccc1394f1cc57642c82ca844cfb043e031c02204292: FOUND -> forge-1.14.3-27.0.60-launcher.jar -> net/minecraftforge/fml/loading/moddiscovery/BackgroundScanHandler.class
SHA256:8805ca6d0fa923ce0bd3eccc1394f1cc57642c82ca844cfb043e031c02204292: FOUND -> forge-1.14.4-28.1.0-installer.jar -> maven/net/minecraftforge/forge/1.14.4-28.1.0/forge-1.14.4-28.1.0.jar -> net/minecraftforge/fml/loading/moddiscovery/BackgroundScanHandler.class
SHA256:bfb3cebdb0c355ac6c9e670cb604b8fd6a03bcfcb9ff63ea8105262feb5fe657: FOUND -> forge-1.16.4-35.1.37-installer.jar -> maven/net/minecraftforge/forge/1.16.4-35.1.37/forge-1.16.4-35.1.37.jar -> net/minecraftforge/fml/loading/moddiscovery/BackgroundScanHandler.class
SHA256:bfb3cebdb0c355ac6c9e670cb604b8fd6a03bcfcb9ff63ea8105262feb5fe657: FOUND -> forge-1.16.5-36.1.18-installer.jar -> maven/net/minecraftforge/forge/1.16.5-36.1.18/forge-1.16.5-36.1.18.jar -> net/minecraftforge/fml/loading/moddiscovery/BackgroundScanHandler.class
```

