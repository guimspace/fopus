# fopus

[![License](https://img.shields.io/badge/license-GPL-blue.svg)](https://github.com/guimspace/fopus/blob/master/LICENSE) [![Version](https://img.shields.io/github/release-pre/guimspace/fopus.svg)](https://github.com/guimspace/fopus/releases)

**Notice** _fopus_ is NOT suitable for professional application as it is not meant to be the most efficient, correct or secure.

## Overview

> *In Linux and Unix, everything is a file.  Directories are files, files are files and devices are files*.  
> Ubuntu documentation - FilePermissions (https://help.ubuntu.com/community/FilePermissions)

**fopus** is a command-line tool for Linux. It is a one-liner command to **archive**, **compress**, **encrypt** and **split** (**aces**) files. It's main purpose is to offer consistency to a series of backups.

- **Archive & compress:** The file is archived and compressed in `.tar.xz` format.  
```
tar -cvpf - -- DIR 2> list-dir_DIR | xz --threads=0 -z -vv - > file_FILE.tar.xz
xz -t -vv file_FILE.tar.xz
```

- **Encrypt:** With `gpg`, the compressed file is encrypted in `.enc` format with the properties: symmetric cipher, sign, compression disabled.  
```
gpg -o file_FILE.tar.xz.enc -u DEFAULT-KEY -s -c -z 0 file_FILE.tar.xz
```

- **Split:** If the encrypted file is larger than `SIZE` bytes, it is split and put `SIZE` bytes per output file.  
```
split --verbose -b SIZE file_FILE.tar.xz.enc file_FILE.tar.xz.enc_
```

### Example

```
$ fopus Photos/
```

**Result:**

The directory `/home/username/Backups/bak_yyyy-mm-dd/` and:
 - `Photos-6910302/` where `6910302` is the first seven digits of SHA1 of `/home/username/Images/Photos`
   - `dir_Photos.tar.xz` the compressed archive
   - `dir_Photos.tar.xz.enc` the encrypted archive
   - `dir_Photos.tar.xz.enc_aa`, `dir_Photos.tar.xz.enc_ab`, ... the pieces of the encrypted archive
   - `list_dir_Photos` a list of files processed in compression
 - `MD5SUMS` and `SHA1SUMS` hashes of files in `Photos-6910302/` to ensure that the data has not changed due to accidental corruption.

The directory `bak_yyyy-mm-dd` have file permission set to `700`. Regular files in `bak_yyyy-mm-dd/` have file permission set to `600`; for directories, `700`.


## Requirements

`gpg`, `curl`, `tar`, `xz`, `split`, `md5sum`, `shasum`


## Install

1. Download `fopus`:

```
$ curl -L https://github.com/guimspace/fopus/releases/latest/download/fopus.sh -o fopus.sh
```

If you do not have `curl`, you can alternatively use a recent `wget`:

```
$ wget https://github.com/guimspace/fopus/releases/latest/download/fopus.sh -O fopus.sh
```

2. Make the installer executable and then execute it:

```
$ chmod u+x fopus.sh
$ sudo ./fopus.sh --install
```

The following GPG key will be used to sign the files and commits:

```
pub   rsa2048/0xEBAE28FD2FEA00BC 2017-11-17 [SC] [expires: 2022-11-16]
      Key fingerprint = 78D3 B7C5 3E14 9768 EBEF  E814 EBAE 28FD 2FEA 00BC
uid                   [ unknown] Guilherme Tadashi Maeoka <gui.mspace@gmail.com>
```


## Usage

**Syntax:** `fopus [OPTION]... [FILE]...`

```
--config                set options
--update                update fopus
--install               install fopus
--uninstall             uninstall fopus
--help                  display a short help and exit
--version               display the version number and exit
```

#### Examples
```
$ fopus Photos/ Documents/ text-file.txt
```


## Contribute code and ideas

Contributors *sign-off* that they adhere to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/) by adding a `Signed-off-by` line to commit messages.

```
$ git commit -s -m 'This is my commit message'
```

For straight forward patches and minor changes, [create a pull request](https://help.github.com/en/articles/creating-a-pull-request).

For larger changes and feature ideas, please open an issue first for a discussion before implementation.


## License

Copyright (C) 2019 Guilherme Tadashi Maeoka  
License GPLv3+: GNU GPL version 3 or later <https://www.gnu.org/licenses/>.
