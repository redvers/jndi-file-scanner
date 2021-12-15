# jndi-file-scanner

Command-line tool to scan .zip/.ear/.war/.jar files recursively for files associated with the log4j vulnerability.

## Status

jndi-file-scanner is "in-flight".  As we are following where the world takes us this tool will change over time.

## Installation

Dependencies:
* libzip (https://libzip.org/)
* pcre2 (https://www.pcre.org/)
* ponyc	(https://github.com/ponylang/ponyc/blob/main/INSTALL.md)
* corral (https://github.com/ponylang/corral)

Get libzip however your distribution packages it.
The Pony Project recommend using ponyup to install ponyc and corral.  Instructions on the website.

### How to build:

As follows in Linux:

```
git clone https://github.com/redvers/jndi-file-scanner
make
```

I have not used any Linux specific code so it should be able to compile for Windows too. YMMV


## Usage

```
usage: jndi-file-scanner [<options>] [<args> ...]

CLI program to help you find vulnerable artifacts

Options:
   -h, --help=false
   -f, --filename            File to search
   -a, --all=false           All filenames
   -r, --regex=JndiLookup    Custom Regex
```

### Example:

```
[nix-shell:~/projects/pony/jndi-file-scanner]$ ./jndi-file-scanner -f testing.zip -r 'log4j.*class' | head -3
FOUND -> testing.zip -> paper-1.18-16.jar -> META-INF/libraries/org/apache/logging/log4j/log4j-iostreams/2.14.1/log4j-iostreams-2.14.1.jar -> org/apache/logging/log4j/io/LoggerFilterWriter.class
FOUND -> testing.zip -> paper-1.18-16.jar -> META-INF/libraries/org/apache/logging/log4j/log4j-iostreams/2.14.1/log4j-iostreams-2.14.1.jar -> org/apache/logging/log4j/io/internal/InternalLoggerReader.class
FOUND -> testing.zip -> paper-1.18-16.jar -> META-INF/libraries/org/apache/logging/log4j/log4j-iostreams/2.14.1/log4j-iostreams-2.14.1.jar -> org/apache/logging/log4j/io/LoggerBufferedReader.class
```

You can see that the tool recursively searched all filenames for the provided regex.

The default regex is /JndiLookup/

#### Case Insensitivity

In order to get case insensitivity, prepend your regex with (?i).

Example:

```
[nix-shell:~/projects/pony/jndi-file-scanner]$ ./jndi-file-scanner -f testing.zip -r '(?i)meta-inf' | head -3
FOUND -> testing.zip -> paper-1.18-16.jar -> META-INF/MANIFEST.MF
FOUND -> testing.zip -> paper-1.18-16.jar -> META-INF/
FOUND -> testing.zip -> paper-1.18-16.jar -> META-INF/main-class
```
