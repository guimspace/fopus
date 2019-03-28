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
typeset -A fopus_config
fopus_config=(
    [min-size]="1073741824"
	[default-key]=""
	[github-username]=""
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
	echo -e "  --dir DIR PASSPHRASE\t\tarchive, compress, encrypt and split"
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
	local github_token=""

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

	if [[ -n "$github_username" ]]; then
		echo -n "fopus: Enter host password for user '$github_username': "
		read -rs github_token
		echo ""
	fi

	if [[ -n "$github_username" ]]; then
		remote_=$(curl -sf --connect-timeout 7 \
			-u "$github_username:$github_token" "$remote_url")
	else
		remote_=$(curl -sf --connect-timeout 7 "$remote_url")
	fi

	if [[ "$?" != 0 ]]; then
		>&2 echo "fopus: update: download failed"
		exit 1
	fi

	remote_hashsum=$(echo "$remote_" | $sha512sum_tool | cut -d " " -f 1)

	fopus_path="/usr/local/bin/fopus"
	if [[ ! -f "$fopus_path" ]]; then
		>&2 echo "fopus: fopus is not installed"
		exit 1
	fi

	local_hashsum=$($sha512sum_tool "$fopus_path" | cut -d " " -f 1)
	if [[ "$local_hashsum" == "$remote_hashsum" ]]; then
		echo "fopus is up-to-date"
		exit 0
	fi

	mkdir -p "$HOME/.fopus/tmp"

	if [[ -n "$github_username" ]]; then
		curl -sf --connect-timeout 7 -u "$github_username:$github_token" \
			-o "$HOME/.fopus/tmp/fopus" "$remote_url"
	else
		curl -sf --connect-timeout 7 \
			-o "$HOME/.fopus/tmp/fopus" "$remote_url"
	fi

	if [[ "$?" != 0 ]]; then
		>&2 echo "fopus: update: download failed"
		exit 1
	fi

	file_="$HOME/.fopus/tmp/fopus"
	download_hashsum=$($sha512sum_tool "$file_" | cut -d " " -f 1)
	if [[ "$remote_hashsum" != "$download_hashsum" ]]; then
		>&2 echo "fopus: update: computed checksum did not match"
		rm -f "$file_"
		exit 1
	fi

	cp "$file_" "/usr/local/bin/fopus"

	chown "$USER:$(id -gn $USER)" "/usr/local/bin/fopus"
	if [[ "$?" != 0 ]]; then error_=1; fi

	chmod 0755 "/usr/local/bin/fopus"
	if [[ "$?" != 0 ]]; then error_=1; fi

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
			fopus_config[default-key]="$conf_value"
			save_conf ;;

		"github-username")
			fopus_config[github-username]="$conf_value"
			save_conf ;;

		*)
			echo "Syntax: fopus --config [OPTION] [ARG]"
			echo ""
			echo "Options:"
			echo ""
			echo -e "  default-key NAME\tuse NAME as the default key to sign with"
			echo -e "  github-username NAME\tGitHub username for authentication"
			;;
	esac
	exit 0
}

fopus_dir()
{
	read_conf

	GPG_KEY_ID=${fopus_config[default-key]}
	TARGET_DIR=$1
	SEC_PASSPHRASE=$2

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


	echo ""
	echo "Start directory"
	cd "$HOME" || exit 1
	mkdir -p "fopus/bak_$DATE"
	cd "fopus/bak_$DATE" || exit 1

	BACKUP_DIR=$(basename "$TARGET_DIR")
	FILE_NAME="dir_$BACKUP_DIR.tar.xz"

	mkdir -p "$BACKUP_DIR"
	cd "$BACKUP_DIR" || exit 1
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
		-c -z 0 \
		--batch --yes --passphrase "$SEC_PASSPHRASE" \
		"$FILE_NAME"
	else
		gpg -o "$FILE_NAME.enc" -u "$GPG_KEY_ID" -s \
		-c -z 0 \
		--batch --yes --passphrase "$SEC_PASSPHRASE" \
		"$FILE_NAME"
	fi
	echo "Done."

	# split
	echo ""
	echo "Split"
	FILE_SIZE=$(stat -c %s "$FILE_NAME.enc")
	if [[ "$FILE_SIZE" -gt "$MIN_SIZE" ]]; then
	  echo ""
	  split --verbose -b 1G "$FILE_NAME.enc" "$FILE_NAME.enc_"
	fi
	echo "Done."

	# hash
	echo ""
	echo "Hash and file permission"
	cd ..
	find "$BACKUP_DIR/" -type f -exec "$sha1sum_tool" {} \; >> SHA1SUMS
	find "$BACKUP_DIR/" -type f -exec md5sum {} \; >> MD5SUMS

	# file permission
	chmod 700 "$BACKUP_DIR/"
	find "$BACKUP_DIR/" -type f -exec chmod 0600 {} \;
	find "$BACKUP_DIR/" -type d -exec chmod 0700 {} \;
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
		fopus_dir "${@:2}" ;;

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
