#!/bin/bash

# fopus: command-line tool to archive, compress, encrypt and split.
# Copyright (C) 2019 Guilherme Tadashi Maeoka
# <https://github.com/guimspace/fopus>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

version=alpha-0.1.0

# https://unix.stackexchange.com/a/232083 for the future
# unset -v password
# set +o allexport

typeset -A fopus_config
fopus_config=(
    [min-size]="1073741824"
	[default-key]=""
	[github-username]=""
	[root-path]="$HOME/Backups/"
)


remote_url="https://raw.githubusercontent.com/guimspace/fopus/master/src/fopus.sh"
MIN_SIZE=1073741824
FOPUS_CONF_PATH="$HOME/.config/fopus/fopus.conf"
FOPUS_CONF_DIR="$HOME/.config/fopus"
DATE=$(date +%Y-%m-%d)

check_requirements()
{
	list_packages=(gpg curl tar xz md5sum shasum)

	for i in ${!list_packages[*]}; do
		if ! command -v "${list_packages[$i]}" &> /dev/null; then
			>&2 echo "fopus: ${list_packages[$i]} not found"
			exit 1
		fi
	done


	sha512sum_func
    if [[ -z "$sha512sum_tool" ]]; then
		>&2 echo "fopus: sha512sum not found"
  		exit 1
    fi

  	sha256sum_func
    if [[ -z "$sha256sum_tool" ]]; then
		>&2 echo "fopus: sha256sum not found"
		exit 1
    fi

	sha1sum_func
    if [[ -z "$sha1sum_tool" ]]; then
		>&2 echo "fopus: sha1sum not found"
		exit 1
    fi
}

sha512sum_func() {
	if command -v sha512sum &> /dev/null; then
		sha512sum_tool="$(command -v sha512sum)"
	elif command -v shasum &> /dev/null; then
		sha512sum_tool="$(command -v shasum) -a 512 "
	fi
	export sha512sum_tool
}

sha256sum_func() {
	if command -v sha256sum &> /dev/null; then
		sha256sum_tool="$(command -v sha256sum)"
	elif command -v shasum &> /dev/null; then
		sha256sum_tool="$(command -v shasum) -a 256 "
	fi
	export sha256sum_tool
}

sha1sum_func() {
	if command -v sha1sum &> /dev/null; then
		sha1sum_tool="$(command -v sha1sum)"
	elif command -v shasum &> /dev/null; then
		sha1sum_tool="$(command -v shasum) "
	fi
	export sha1sum_tool
}

show_version()
{
	echo "fopus $version"
	echo "Copyright (C) 2019 Guilherme Tadashi Maeoka"
	echo "License GPLv3+: GNU GPL version 3 or later <https://www.gnu.org/licenses/>."
	echo "This is free software: you are free to change and redistribute it."
	echo "There is NO WARRANTY, to the extent permitted by law."

}

show_help()
{
	echo "Usage: fopus [OPTION]... [DIRECTORY]"
	echo "Archive, compress, encrypt and split a DIRECTORY."
	echo ""
	echo "Examples:"
	echo "  fopus --dir /home/username/Documents/foo/"
	echo "  fopus --dir foo/"
	echo ""
	echo -e "  --dir DIR\t\t\tarchive, compress, encrypt and split"
	echo -e "  --config\t\t\tset options"
	echo -e "  --update\t\t\tupdate fopus"
	echo -e "  --install\t\t\tinstall fopus"
	echo -e "  --uninstall\t\t\tuninstall fopus"
	echo -e "  --help\t\t\tdisplay this short help and exit"
	echo -e "  --version\t\t\tdisplay the version number and exit"
	echo ""
	# echo "directory (--dir)"
	# echo "  All files are saved in '\$HOME/fopus/bak_yyyy-mm-dd/DIR/'."
	# echo "  The sequence of processes is archive & compress > encrypt > split > hash & file permission."
	# echo ""
	# echo "    archive & compress: The DIR is archived and compressed in .tar.xz format. A list of files processed is save in the text file 'list-dir_DIR'. After compression, test compressed file integrity."
	# echo -e "\t\$ tar -cJvpf dir_DIR.tar.xz -- DIR > \"list-dir_DIR\""
	# echo -e "\t\$ xz -tv -- \"dir_DIR.tar.xz\""
	# echo ""
	# echo "    encrypt: The compressed archive is encrypted with gpg in .enc format under the following properties: sign, symmetric cipher, compression disabled."
	# echo -e "\t\$ gpg -o \"dir_DIR.tar.xz.enc\" [-u \"default-key\"] -s -c -z 0 --batch --yes --passphrase \"PASSPHRASE\" \"dir_DIR.tar.xz\""
	# echo ""
	# echo "    split: If the encrypted file size is larger than 1073741824 bytes, it is split and put 1073741824 bytes per output file. The prefix used is 'dir_DIR.tar.xz.enc_'."
	# echo -e "\t\$ split --verbose -b 1G \"dir_DIR.tar.xz.enc\" \"dir_DIR.tar.xz.enc_\""
	# echo ""
	# echo "    hash & file permission: All files are hashed with SHA1 and MD5 to ensure that the data has not changed due to accidental corruption. The hashes are saved in the parent directory. The file permission set for FILE is 0600, and for DIRECTORY is 0700."
	# echo -e "\t\$ find \"DIR/\" -type f -exec sha1sum {} \; >> SHA1SUMS"
	# echo -e "\t\$ find \"DIR/\" -type f -exec chmod 0600 {} \;"
	# echo ""
	echo "Report bugs, comments and suggestions to <gui.mspace@gmail.com> (in English or Portuguese)."
	echo "fopus repository: <https://github.com/guimspace/fopus>"
}

install_fopus()
{
	error_=0

	if [[ ! -d "/usr/local/bin/" ]]; then
		>&2 echo "fopus: /usr/local/bin/ not found."
		exit 1
	fi

	cli="$(cd "$(dirname "$0")" && pwd -P)/$(basename "$0")"
	cp "$cli" "/usr/local/bin/fopus"
	if [[ "$?" != 0 ]]; then exit 1; fi

	chown "$USER:$(id -gn $USER)" "/usr/local/bin/fopus"
	if [[ "$?" != 0 ]]; then error_=1; fi

	chmod 0755 "/usr/local/bin/fopus"
	if [[ "$?" != 0 ]]; then error_=1; fi

	if [[ "$error_" == 0 ]]; then
		init_conf
		echo "Done."
		exit 0
	else
		>&2 echo "fopus: install failed."
		exit 1
	fi
}

uninstall_fopus()
{
	error_=0

	rm -f "/usr/local/bin/fopus"
	if [[ "$?" != 0 ]]; then error_=1; fi

	if [[ "$error_" == 0 ]]; then
		echo "Done."
		exit 0
	else
		>&2 echo "fopus: uninstall failed."
		exit 1
	fi
}

update_fopus()
{
	read_conf
	local github_username=""

	fopus_path="/usr/local/bin/fopus"
	if [[ ! -f "$fopus_path" ]]; then
		>&2 echo "fopus: fopus is not installed"
		exit 1
	fi

	if [[ "$1" == "-u" ]]; then
		if [[ -z "$2" ]]; then
			>&2 echo "fopus: update: missing GitHub username"
			echo -n "fopus: update: drop authentication and continue? [Y/n]: "
			read -r user_answer
			if [[ "$user_answer" == "n" || "$user_answer" == "N" ]]; then
				exit 1
			fi
		fi
		github_username="$2"
	else
		github_username="${fopus_config[github-username]}"
	fi

	if ! mkdir -p "/tmp/fopus/"; then
		exit 1
	fi

	if [[ -f "/tmp/fopus/fopus" ]]; then
		rm -f "/tmp/fopus/fopus"
	fi

	if [[ -n "$github_username" ]]; then
		curl -sf --connect-timeout 7 -o "/tmp/fopus/fopus" \
			-u "$github_username" "$remote_url"
	else
		curl -sf --connect-timeout 7 -o "/tmp/fopus/fopus" "$remote_url"
	fi

	dl_file="/tmp/fopus/fopus"
	if [[ ! -f "$dl_file" ]]; then
		>&2 echo "fopus: update: download failed"
		exit 1
	fi

	remote_hashsum=$($sha512sum_tool "$dl_file" | cut -d " " -f 1)

	local_hashsum=$($sha512sum_tool "$fopus_path" | cut -d " " -f 1)
	if [[ "$local_hashsum" == "$remote_hashsum" ]]; then
		echo "fopus is up-to-date"
		exit 0
	fi

	echo "Updating..."

	cp "$dl_file" "/usr/local/bin/fopus"
	chown "$USER:$(id -gn $USER)" "/usr/local/bin/fopus"
	chmod 0755 "/usr/local/bin/fopus"

	echo "fopus is up-to-date"
	exit 0
}

init_conf()
{
	if [[ -f "$FOPUS_CONF_PATH" ]]; then
		return
	fi

	if [[ ! -d "$FOPUS_CONF_DIR" ]]; then
		mkdir -p "$FOPUS_CONF_DIR"

		chown "$SUDO_USER:$(id -gn $SUDO_USER)" "$FOPUS_CONF_DIR"
		if [[ "$?" != 0 ]]; then exit 1; fi

		chmod 0700 "$FOPUS_CONF_DIR"
		if [[ "$?" != 0 ]]; then exit 1; fi
	fi

	echo "min-size 1073741824" > "$FOPUS_CONF_PATH"

	chown "$SUDO_USER:$(id -gn $SUDO_USER)" "$FOPUS_CONF_PATH"
	if [[ "$?" != 0 ]]; then exit 1; fi

	chmod 0600 "$FOPUS_CONF_PATH"
	if [[ "$?" != 0 ]]; then exit 1; fi
}

read_conf()
{
	if [[ ! -f "$FOPUS_CONF_PATH" ]]; then
		exit 1
	fi

	while read var value; do
		if [[ ! -z "$var" && ! -z "$value" ]]; then
			fopus_config["$var"]="$value"
		fi
	done < "$FOPUS_CONF_PATH"
}

save_conf()
{
	if [[ ! -f "$FOPUS_CONF_PATH" ]]; then
		init_conf
	fi

	echo "" > "$FOPUS_CONF_PATH"
	for var in ${!fopus_config[*]}; do
		if [[ ! -z ${fopus_config[$var]} ]]; then
			echo "$var ${fopus_config[$var]}" >> "$FOPUS_CONF_PATH"
		fi
	done
}

config_fopus()
{
	read_conf

	conf_option="$1"
	conf_value="$2"

	case "$conf_option" in
		"default-key")
			fopus_config[default-key]="$conf_value" ;;

		"github-username")
			fopus_config[github-username]="$conf_value" ;;

		"root-path")
			if [[ "$conf_value" == "$HOME" || "$conf_value" == "$HOME/" ]]; then
				conf_value=""
			elif [[ ! -d "$conf_value" ]]; then
				>&2 echo "fopus: invalid operand"
				exit 1
			else
				cd $(dirname "$conf_value") || exit 1
				conf_value="$(pwd -P)/$(basename "$conf_value")/"

				if [[ ! "$conf_value" =~ ^"$HOME"* ]]; then
					>&2 echo "fopus: permission denied"
					exit 1
				fi
			fi

			fopus_config[root-path]="$conf_value" ;;

		"min-size")
			if [[ "$conf_value" == "0" ]]; then
				conf_value=""
			fi

			fopus_config[min-size]="$conf_value" ;;

		*)
			echo "Syntax: fopus --config [OPTION] [ARG]"
			echo ""
			echo "Options:"
			echo ""
			echo -e "  default-key NAME\tuse NAME as the default key to sign with"
			echo -e "  min-size SIZE\tput SIZE bytes per output file; 0 and blank defaults to 1073741824"
			echo -e "  root-path DIR\tput backups in \$HOME/DIR/; blank defaults to '\$HOME/Backups'"
			echo -e "  github-username NAME\tGitHub username for authentication"
			exit 0 ;;
	esac

	save_conf
	exit 0
}

fopus_dir()
{
	read_conf

	TARGET_DIR="$1"
	GPG_KEY_ID="${fopus_config[default-key]}"

	if [[ ! -z "$GPG_KEY_ID" ]]; then
		gpg --list-secret-key "$GPG_KEY_ID" 1> /dev/null
		if [[ "$?" -ne 0 ]]; then exit 1; fi
	fi

	if [[ -z "$TARGET_DIR" ]]; then
		>&2 echo "fopus: missing operand"
		exit 1
	elif [[ "$TARGET_DIR" == "$HOME" || "$TARGET_DIR" == "$HOME/" ]]; then
		>&2 echo "fopus: missing operand"
		exit 1
	elif [[ ! -d "$TARGET_DIR" ]]; then
		>&2 echo "fopus: invalid operand"
		exit 1
	fi

	cd $TARGET_DIR || exit 1
	TARGET_DIR=$(pwd -P)
	cd ..

	if [[ ! "$TARGET_DIR" =~ ^"$HOME"* ]]; then
		>&2 echo "fopus: invalid operand"
		exit 1
	fi

	root_path="${fopus_config[root-path]}"
	if [[ "$root_path" == "$HOME" || "$root_path" == "$HOME/" ]]; then
		root_path="Backups"
	elif [[ ! -d "$root_path" ]]; then
		>&2 echo "fopus: '$root_path' is not a directory"
		exit 1
	elif [[ ! "$root_path" =~ ^"$HOME"* ]]; then
		>&2 echo "fopus: permission denied"
		exit 1
	fi

	mkdir -p "$root_path"

	echo ""
	echo "Start directory"
	cd "$HOME" || exit 1

	mkdir -p "$root_path/bak_$DATE"
	cd "$root_path/bak_$DATE" || exit 1

	BACKUP_DIR=$(basename "$TARGET_DIR")
	FILE_NAME="dir_$BACKUP_DIR.tar.xz"

	dir_hash=$(echo "$TARGET_DIR" | "$sha1sum_tool")
	BACKUP_DIR_HASH="$BACKUP_DIR-${dir_hash:0:7}"
	mkdir -p "$BACKUP_DIR_HASH"
	cd "$BACKUP_DIR_HASH" || exit 1
	echo "Done."


	# compress
	echo ""
	echo "Compression"
	tar -cJvpf "$FILE_NAME" -- "$TARGET_DIR" > "list-dir_$BACKUP_DIR"
	echo "Done."

	# test compression
	echo ""
	echo "Test compression"
	xz -tv -- "$FILE_NAME"
	if [[ $? -ne 0 ]]; then exit 1; fi
	echo "Done."

	# encrypt
	echo ""
	echo "Encrypt"
	if [[ -z "$GPG_KEY_ID" ]]; then
		gpg -o "$FILE_NAME.enc" -s \
			-c -z 0 "$FILE_NAME"
	else
		gpg -o "$FILE_NAME.enc" -u "$GPG_KEY_ID" -s \
			-c -z 0 "$FILE_NAME"
	fi
	echo "Done."

	# split
	echo ""
	echo "Split"
	split_size=${fopus_config[min-size]}
	file_size=$(stat -c %s "$FILE_NAME.enc")
	if [[ "$file_size" -gt "$split_size" ]]; then
	  echo ""
	  split --verbose -b "$split_size" "$FILE_NAME.enc" "$FILE_NAME.enc_"
	fi
	echo "Done."

	# hash
	echo ""
	echo "Hash and file permission"
	cd ..
	find "$BACKUP_DIR_HASH/" -type f -exec "$sha1sum_tool" {} \; >> SHA1SUMS
	find "$BACKUP_DIR_HASH/" -type f -exec md5sum {} \; >> MD5SUMS

	# file permission
	chmod 700 "$BACKUP_DIR_HASH/"
	find "$BACKUP_DIR_HASH/" -type f -exec chmod 0600 {} \;
	find "$BACKUP_DIR_HASH/" -type d -exec chmod 0700 {} \;
	echo "Done."

	exit 0
}


check_requirements

user_input="$1"
if [[ "$user_input" == "--install" || "$user_input" == "--uninstall" || \
		"$user_input" == "--update" ]]; then
	if [[ "$UID" != 0 ]]; then
		>&2 echo "fopus: permission denied"
		exit 1
	fi
fi

case "$user_input" in
	"--install")
		install_fopus ;;

	"--uninstall")
		uninstall_fopus ;;

	"--update")
		update_fopus "${@:2}" ;;

	"--dir")
		fopus_dir "$2" ;;

	"--config")
		config_fopus "${@:2}" ;;

	"--help")
		show_help ;;

	"--version")
		show_version ;;

	*)
		echo "Try 'fopus --help' for more information." ;;
esac
exit 0
