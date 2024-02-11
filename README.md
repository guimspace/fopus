# fopus

[![License](https://img.shields.io/github/license/guimspace/fopus)](https://github.com/guimspace/fopus/blob/master/LICENSE) [![Version](https://img.shields.io/github/release-pre/guimspace/fopus.svg)](https://github.com/guimspace/fopus/releases)

**Notice** _fopus_ is NOT suitable for professional application as it is not meant to be the most efficient, correct or secure.

# Overview

> *In Linux and Unix, everything is a file.  Directories are files, files are files and devices are files*.
> Ubuntu documentation - [FilePermissions](https://help.ubuntu.com/community/FilePermissions) (as 2022-12-12)

**fopus** is a command-line tool for Linux. It is a one-liner command to **archive**, **compress**, **encrypt**, **split**, **hash** and **sign** files. It aims consistency in the process of backup.

Backup archive is encrypted by [**age**](https://github.com/FiloSottile/age) with a passphrase. An age identity key is not required.

Large backups are split in pieces of 1G.

Hashes are signed by [**minisign**](https://github.com/jedisct1/minisign). A minisign secret key is required.

### Process summary

- **Archive & compress:** The file is archived and compressed in `.tar.xz` format.
```
tar -cvpf - -- FILE 2> list_FILE.txt | xz --threads=0 -z - > FILE.tar.xz
```

- **Encrypt:** With `age`, the compressed file is encrypted in `.age` format.
```
age --encrypt --passphrase FILE.tar.xz > FILE.tar.xz.age
```

- **Split:** If the encrypted file is larger than `SIZE` bytes, it is split and put `SIZE` bytes per output file.
```
split -b SIZE FILE.tar.xz.age FILE.tar.xz.age_
```

- **Hash:** Files are hashed with SHA-256.
```
sha256sum FILE.tar.xz FILE.tar.xz.age [FILE.tar.xz.age_aa ...] list_FILE.txt > SHA256SUMS
```

- **Sign:** The hashes are signed with `minisign`.
```
minisign -Sm SHA256SUMS
```

- **Permissions:** Permission of files are set to 600, and 700 for directories.

### Example

```
$ fopus Photos/
```

**Output:**

A directory `./Backups/backup_yyyy-mm-dd/` and:
 - `Photos-15e2ef83315/` where `15e2ef83315` is the first eleven digits of SHA-1 of `/home/username/Images/Photos`
   - `Photos.tar.xz` the compressed archive
   - `Photos.tar.xz.age` the encrypted archive
   - `Photos.tar.xz.age_aa`, `Photos.tar.xz.age_ab`, ... the pieces of the encrypted archive
   - `list_Photos.txt` a list of files processed in compression
 - `SHA1SUMS` hash of files in `Photos-15e2ef83315/` to ensure that the data has not changed due to accidental corruption.

The directory `backup_yyyy-mm-dd` have file permission set to `700`. Regular files in `backup_yyyy-mm-dd/` have file permission set to `600`; for directories, `700`.


# Requirements

`age`, `minisign`, `xz`


# Install

```
sudo curl -L https://github.com/guimspace/fopus/releases/latest/download/fopus.sh -o /usr/local/bin/fopus
sudo chmod a+rx /usr/local/bin/fopus
```


# Usage

**Syntax:** `fopus [-1sgn] [-b SIZE] [-o OUTPUT] [-k SECKEY] FILE...`

```
-1		Put FILEs in one backup.
-s		Don't split backup in parts.
-b SIZE		Split backup pieces of SIZE. Default is 1G.
-g		Group backups by file/date instead of date/name.
-o OUTPUT	Backup in the directory at path OUTPUT.
-k SECKEY	Minisign with SECKEY.
-n		Don't perform any action.
```

### Examples

```
$ fopus -o ~/Backups -b 1G Documents/ lorem-ipsum.txt
$ fopus -1s Pictures/ Videos/
```

# Contribute code and ideas

Contributors *sign-off* that they adhere to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/) by adding a `Signed-off-by` line to commit messages.

```
$ git commit -s -m 'This is my commit message'
```

For straight forward patches and minor changes, [create a pull request](https://help.github.com/en/articles/creating-a-pull-request).

For larger changes and feature ideas, please open an issue first for a discussion before implementation.


# License

Copyright (C) 2019-2022 Guilherme Tadashi Maeoka

2022 MIT License

2019-2022 License GPLv3+: GNU GPL version 3 or later <https://www.gnu.org/licenses/>.
