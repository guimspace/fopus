# fopus

[![License](https://img.shields.io/github/license/guimspace/fopus)](https://github.com/guimspace/fopus/blob/master/LICENSE) [![Version](https://img.shields.io/github/release-pre/guimspace/fopus.svg)](https://github.com/guimspace/fopus/releases)

**Notice** _fopus_ is NOT suitable for professional application as it is not meant to be the most efficient, correct or secure.

## Overview

> *In Linux and Unix, everything is a file.  Directories are files, files are files and devices are files*.  
> Ubuntu documentation - FilePermissions (https://help.ubuntu.com/community/FilePermissions)

**fopus** is a command-line tool for Linux. It is a one-liner command to **archive**, **compress**, **encrypt**, **split**, **hash** and **sign** files. It's main purpose is to offer consistency in a series of backups.

- **Archive & compress:** The file is archived and compressed in `.tar.xz` format.  
```
tar -cvpf - -- FILE 2> list_FILE.txt | xz --threads=0 -z -vv - > FILE.tar.xz
```

- **Encrypt:** With `age`, the compressed file is encrypted in `.age` format.  
```
age -p FILE.tar.xz > FILE.tar.xz.age
```

- **Split:** If the encrypted file is larger than `SIZE` bytes, it is split and put `SIZE` bytes per output file.  
```
split --verbose -b SIZE FILE.tar.xz.enc FILE.tar.xz.enc_
```

- **Hash:** All files are hashes with SHA-256
```
sha256sum FILE.tar.xz FILE.tar.xz.age [FILE.tar.xz.age_aa ...] list_FILE > SHA256SUMS
```

- **Sign:** The hashes are signed with `minisign`.
```
minisign -Sm SHA256SUMS
```

### Example

```
$ fopus Photos/
```

**Result:**

The directory `/home/username/Backups/backup_yyyy-mm-dd/` and:
 - `Photos-15e2ef83315/` where `15e2ef83315` is the first eleven digits of SHA1 of `/home/username/Images/Photos`
   - `dir_Photos.tar.xz` the compressed archive
   - `dir_Photos.tar.xz.age` the encrypted archive
   - `dir_Photos.tar.xz.age_aa`, `dir_Photos.tar.xz.age_ab`, ... the pieces of the encrypted archive
   - `list_Photos.txt` a list of files processed in compression
 - `MD5SUMS` and `SHA1SUMS` hashes of files in `Photos-15e2ef83315/` to ensure that the data has not changed due to accidental corruption.

The directory `bak_yyyy-mm-dd` have file permission set to `700`. Regular files in `backup_yyyy-mm-dd/` have file permission set to `600`; for directories, `700`.


## Requirements

`age`, `minisign`, `xz`


## Install

1. Download `fopus`:

```
$ sudo curl -L https://github.com/guimspace/fopus/releases/latest/download/fopus.sh -o /usr/local/bin/fopus
```

2. Make the installer executable and then execute it:

```
$ sudo chmod a+rx /usr/local/bin/fopus
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

Copyright (C) 2019-2022 Guilherme Tadashi Maeoka

2022 MIT License

2019-2022 License GPLv3+: GNU GPL version 3 or later <https://www.gnu.org/licenses/>.
