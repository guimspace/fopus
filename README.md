# fopus

[![License](https://img.shields.io/github/license/guimspace/fopus)](https://github.com/guimspace/fopus/blob/master/LICENSE) [![Version](https://img.shields.io/github/release-pre/guimspace/fopus.svg)](https://github.com/guimspace/fopus/releases)

**Notice** _fopus_ is NOT suitable for professional application as it is not meant to be the most efficient, correct or secure.

# Overview

> *In Linux and Unix, everything is a file.  Directories are files, files are files and devices are files*.
> Ubuntu documentation - [FilePermissions](https://help.ubuntu.com/community/FilePermissions) (as 2022-12-12)

**fopus** is a command-line tool for Linux. It is a one-liner command to **archive**, **compress**, **encrypt**, **split**, **hash** and **sign** files. It aims consistency in the process of backup.

Backup archive is encrypted by [**age**](https://github.com/FiloSottile/age) with a passphrase or to a recipient.

Large backups are split in pieces of 2G by default.

Hashes are signed by [**minisign**](https://github.com/jedisct1/minisign).

### Process summary

- **Archive & compress:** The file is archived and compressed in `.tar.xz` format.
```
tar -cvvpf - -- FILE 2> FILE.txt | xz --threads=0 -z - > FILE.tar.xz
```

- **Encrypt:** With `age`, the compressed file is encrypted in `.age` format.
```
age --encrypt --passphrase FILE.tar.xz > FILE.tar.xz.age
age --encrypt --recipient RECIPIENT FILE.tar.xz > FILE.tar.xz.age
age --encrypt --recipients-file PATH FILE.tar.xz > FILE.tar.xz.age
age --encrypt --identity PATH FILE.tar.xz > FILE.tar.xz.age
```

- **Split:** If the encrypted file is larger than `SIZE` bytes, then it is split and put `SIZE` bytes per output file.
```
split -b SIZE FILE.tar.xz.age FILE.tar.xz.age_
```

- **Checksum:** Files are hashed with BLAKE3, BLAKE2, or SHA-256.
```
b3sum FILE.tar.xz FILE.tar.xz.age [FILE.tar.xz.age_aa ...] FILE.list.txt > CHECKSUMS.txt
b2sum FILE.tar.xz FILE.tar.xz.age [FILE.tar.xz.age_aa ...] FILE.list.txt > CHECKSUMS.txt
sha256sum FILE.tar.xz FILE.tar.xz.age [FILE.tar.xz.age_aa ...] FILE.list.txt > CHECKSUMS.txt
```

- **Sign:** The hashes are signed with `minisign` when a secret key is provided.
```
minisign -s KEY [-t COMMENT] -Sm CHECKSUMS.txt
```

- **Permissions:** Permission of files are set to 600, and 700 for directories.

- **Label:** A text file label is created with a random UUID, a timestamp, the absoluate pathname of `FILE`, and the SHA-1 hashes of the output.

### Example

```
$ cd ~/Images
$ fopus Photos/
```

**Output:**

A directory `./backup_yyyy-mm-dd/` and:
 - `Photos-15e2ef83315/` where `15e2ef83315` is the first eleven digits of SHA-1 of `/home/username/Images/Photos`
   - `Photos.tar.xz` the compressed archive (plaintext)
   - `Photos.tar.xz.age` the encrypted archive
   - `Photos.tar.xz.age_aa`, `Photos.tar.xz.age_ab`, ... the pieces of the encrypted archive
   - `Photos.list.txt` a list of files processed in compression (plaintext)
   - `label.txt` a label with a random UUID, a timestamp, an absoluate pathname, and SHA-1
   - `CHECKSUMS.txt` checksums of the files
   - `CHECKSUMS.txt.minisign` signature of the checksums
 - `SHA1SUMS.txt` hash of files in `Photos-15e2ef83315/` to ensure that the data has not changed due to accidental corruption - if label option is not select.

The directory `backup_yyyy-mm-dd` have file permission set to `700`. Regular files in `backup_yyyy-mm-dd/` have file permission set to `600`; for directories, `700`.


# Requirements

`age`, `minisign`, `xz`


# Install

```
sudo curl -L https://github.com/guimspace/fopus/releases/latest/download/fopus.sh -o /usr/local/bin/fopus
sudo chmod a+rx /usr/local/bin/fopus
```


# Usage

**Syntax:**
```
fopus [-1gnql] [-b SIZE] [-o OUTPUT] \
    [-s SECKEY] [-t COMMENT] \
    [-r RECIPIENT] [-R PATH] [-i PATH] FILE...
```

**Options:**
```
-1            Put FILEs in one backup.
-2            Use standard SHA-256 for checksums.
-g            Group backups by file/date instead of date/name.
-o OUTPUT     Put the backup in path OUTPUT.
-n            Don't perform any action.
-q            Quieter mode.
-l            Create a label for the backup.
-b SIZE       Split backup pieces of SIZE. Default is 2G.
              Specify 0 to not split.

-s SECKEY     Minisign with SECKEY.
-t COMMENT    Minisign add a one-line trusted COMMENT.

-r RECIPIENT  Age encrypt to the specified RECIPIENT.
-R PATH       Age encrypt to recipients listed at PATH.
-i PATH       Age encrypt to identity file at PATH.
```

### Examples

```
$ fopus -o ~/Backups -b 1G Documents/ lorem-ipsum.txt
$ fopus -1 -b 0 -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p Pictures/ Videos/
$ fopus -l -s ~/.minisign/minisign.key -t "Trusted lorem ipsum" -R ~/.age/projects.pub Projects/
$ fopus -2lq -i ~/.age/backup.key Memes/
```

# Contribute code and ideas

Contributors *sign-off* that they adhere to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/) by adding a `Signed-off-by` line to commit messages.

```
$ git commit -s -m 'This is my commit message'
```

For straight forward patches and minor changes, [create a pull request](https://help.github.com/en/articles/creating-a-pull-request).

For larger changes and feature ideas, please open an issue first for a discussion before implementation.


# License

Copyright (C) 2019-2024 Guilherme Tadashi Maeoka

2022-2024 MIT License

2019-2022 License GPLv3+: GNU GPL version 3 or later <https://www.gnu.org/licenses/>.
