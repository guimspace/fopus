# fopus

[![License](https://img.shields.io/badge/license-GPL-blue.svg)](https://github.com/guimspace/fopus/blob/master/LICENSE)


## Overview

**fopus** is a command-line tool for Linux. It is a one-liner command to **archive**, **compress**, **encrypt** and **split** a directory.

1. **Archive & compress:** The directory is archived and compressed in `.tar.xz` format.  
`$ tar -I ALGO -cvpf dir_DIR.tar.xz -- DIR > list-dir_DIR`

2. **Encrypt:** With `gpg`, the compressed file is encrypted with the properties: symmetric cipher, sign, compression disabled.  
```
$ gpg -o dir_DIR.tar.xz.enc -u DEFAULT-KEY -s -c -z 0 dir_DIR.tar.xz
```

3. **Split:** If the encrypted file is larger than 1073741824 bytes, it is split and put 1073741824 bytes per output file.  
`$  split --verbose -b SIZE dir_DIR.tar.xz.enc dir_DIR.tar.xz.enc_`


## Requirements

`gpg`, `curl`, `tar`, `xz` or `pxz`, `md5sum`, `shasum`


## Install

1. Download `fopus`:

```
wget https://raw.githubusercontent.com/guimspace/fopus/master/src/fopus.sh -O fopus.sh
```

2. Make the installer executable and then execute it:

```
chmod u+x fopus.sh
sudo ./fopus.sh --install
```

3. Set the default GPG key to sign with:
```
fopus --config default-key [GPG KEY ID]
```


## Usage

**Syntax:** `fopus [OPTION]... [DIRECTORY PASSPHRASE]`

```
--dir DIR               archive, compress, encrypt and split
--config                set options
--update                update fopus
--install               install fopus
--uninstall             uninstall fopus
--help                  display a short help and exit
--version               display the version number and exit
```

#### Examples
```
fopus --dir /home/USERNAME/Documents/foo/
fopus --dir foo/
```


## License

Copyright (C) 2019 Guilherme Tadashi Maeoka  
License GPLv3+: GNU GPL version 3 or later <https://www.gnu.org/licenses/>.
