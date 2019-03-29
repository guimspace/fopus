# fopus

[![License](https://img.shields.io/badge/license-GPL-blue.svg)](https://github.com/guimspace/fopus/blob/master/LICENSE)


## Overview

**fopus** is a command-line tool for Linux. It is a one-liner command to **archive**, **compress**, **encrypt** and **split** (aces) a directory. It's main purpose is to reduce the hassles of remembering the correct command names and options, and to automate the **aces** with consistency.

1. **Archive & compress:** The directory is archived and compressed in `.tar.xz` format.  
```
tar -I ALGO -cvpf dir_DIR.tar.xz -- DIR > list-dir_DIR
```

2. **Encrypt:** With `gpg`, the compressed file is encrypted with the properties: symmetric cipher, sign, compression disabled.  
```
gpg -o dir_DIR.tar.xz.enc -u DEFAULT-KEY -s -c -z 0 dir_DIR.tar.xz
```

3. **Split:** If the encrypted file is larger than 1073741824 bytes, it is split and put 1073741824 bytes per output file.  
```
split --verbose -b SIZE dir_DIR.tar.xz.enc dir_DIR.tar.xz.enc_
```

### Example

```
$ fopus --dir Photos/
```

**Result:**

The directory `/home/username/Backups/bak_yyyy-mm-dd/` and:
 - `Photos-0989ee4/` where `0989ee4` is the first seven digits of SHA1 of `/home/username/Images/Photos/`
   - `dir_Photos.tar.xz` the compressed archive
   - `dir_Photos.tar.xz.enc` the encrypted archive
   - `dir_Photos.tar.xz.enc_aa`, `dir_Photos.tar.xz.enc_ab`, ... the pieces of the encrypted archive
   - `list-dir_Photos` a list of files processed in compression
 - `MD5SUMS` and `SHA1SUMS` hashes of files in `Photos-0989ee4/` to ensure that the data has not changed due to accidental corruption.

The directory `bak_yyyy-mm-dd` have file permission set to `0700`. Regular files in `bak_yyyy-mm-dd/` have file permission set to `0600`; for directories, `0700`.


## Requirements

`gpg`, `curl`, `tar`, `xz` or `pxz`, `md5sum`, `shasum`


## Install

1. Download `fopus`:

```
curl https://raw.githubusercontent.com/guimspace/fopus/master/src/fopus.sh -o fopus.sh
```

If you do not have `curl`, you can alternatively use a recent `wget`:

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

The following GPG key will be used to sign the files and commits:

```
pub   rsa2048/0xEBAE28FD2FEA00BC 2017-11-17 [SC] [expires: 2022-11-16]
      Key fingerprint = 78D3 B7C5 3E14 9768 EBEF  E814 EBAE 28FD 2FEA 00BC
uid                   [ unknown] Guilherme Tadashi Maeoka <gui.mspace@gmail.com>
sub   rsa2048/0xBF76CF49CA921C51 2017-11-17 [E] [expires: 2022-11-16]
```


## Usage

**Syntax:** `fopus [OPTION]... [DIRECTORY]`

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
$ fopus --dir /home/username/Images/Photos/
$ fopus --dir Photos/
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
