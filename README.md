# decomp

Terminal tool for decompiling a jar with Vineflower and poking around the output.

## Requirements

- Python 3
- Java (on PATH)
- openssl (on PATH, optional, used for reading x509 certs)
- vineflower.jar in this folder

## Usage

```
python3 decomp.py
```

Pick a jar, pick an output folder, wait for it to decompile. It also pulls
every readable string out of the jar into `strings.txt`, and any base64 it
finds gets decoded into `base64.txt`. If a decoded blob or a PEM block turns
out to be an x509 cert, the parsed cert info gets dropped in there too.

Once that's done you get a file browser (parent / current / preview columns,
like lf).

## Keys

```
j/k       move up/down
h/l       go up a folder / open folder or file
gg / G    jump to top/bottom
/         search, n for next match
s         open strings.txt
b         open base64.txt
r         decompile another jar
q         quit
```

Suspicious lines (URLs, IPs, exec/reflection calls, base64, etc) show up
highlighted when viewing files or strings.
