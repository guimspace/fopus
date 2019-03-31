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

version=alpha-0.2.0

# https://unix.stackexchange.com/a/232083 for the future
# unset -v password
# set +o allexport

typeset -A fopus_config
fopus_config=(
    [min-size]="1073741824"
	[default-key]=""
	[github-username]=""
	[root-path]="$HOME/Backups/"
	[compress-algo]="xz"
	[destroy]="false"
)


remote_url="https://raw.githubusercontent.com/guimspace/fopus/master/src/fopus.sh"
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

	chown "$USER:$(id -gn "$USER")" "/usr/local/bin/fopus"
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
	chown "$USER:$(id -gn "$USER")" "/usr/local/bin/fopus"
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

		chown "$SUDO_USER:$(id -gn "$SUDO_USER")" "$FOPUS_CONF_DIR"
		if [[ "$?" != 0 ]]; then exit 1; fi

		chmod 0700 "$FOPUS_CONF_DIR"
		if [[ "$?" != 0 ]]; then exit 1; fi
	fi

	echo "min-size 1073741824" > "$FOPUS_CONF_PATH"

	chown "$SUDO_USER:$(id -gn "$SUDO_USER")" "$FOPUS_CONF_PATH"
	if [[ "$?" != 0 ]]; then exit 1; fi

	chmod 0600 "$FOPUS_CONF_PATH"
	if [[ "$?" != 0 ]]; then exit 1; fi
}

read_conf()
{
	if [[ ! -f "$FOPUS_CONF_PATH" ]]; then
		exit 1
	fi

	while read -r var value; do
		if [[ -n "$var" && -n "$value" ]]; then
			fopus_config["$var"]="$value"
		elif [[ -z "$value" ]]; then
			case "$var" in

			esac
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
		if [[ -n ${fopus_config[$var]} ]]; then
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

		"compress-algo")
			if [[ -z "$conf_value" || "$conf_value" == "1" ]]; then
				conf_value="xz"
			elif [[ "$conf_value" == "2" ]]; then
				conf_value="pxz"
			else
				>&2 echo "fopus: invalid operand"
				exit 1
			fi

			fopus_config[compress-algo]="$conf_value" ;;

		"root-path")
			if [[ "$conf_value" == "$HOME" || "$conf_value" == "$HOME/" ]]; then
				conf_value=""
			elif [[ ! -d "$conf_value" ]]; then
				>&2 echo "fopus: invalid operand"
				exit 1
			else
				cd "$(dirname "$conf_value")" || exit 1
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

		destroy)
			if [[ "$conf_value" == "true" || "$conf_value" == "false" ]]; then
				fopus_config[destroy]="$conf_value"
			else
				>&2 echo "fopus: config: invalid arg"
				exit 1
			fi ;;

		*)
			echo "Syntax: fopus --config [OPTION] [ARG]"
			echo ""
			echo "Options:"
			echo ""
			echo -e "  default-key NAME\tuse NAME as the default key to sign with"
			echo -e "  min-size SIZE\tput SIZE bytes per output file; 0 and blank defaults to 1073741824"
			echo -e "  compress-algo n\tuse compress algorithm n; default is 1 which is xz; use 2 to use pxz"
			echo -e "  root-path DIR\tput backups in \$HOME/DIR/; blank defaults to '\$HOME/Backups'"
			echo -e "  destroy BOOL\tremove compressed archive after encryption"
			echo -e "  github-username NAME\tGitHub username for authentication"
			exit 0 ;;
	esac

	save_conf
	exit 0
}

fopus_main()
{
	read_conf

	user_answer=""

	fopus_input=("$@")
	declare -a list_files
	declare -a list_clean

	origins="$(pwd -P)"
	root_path="${fopus_config[root-path]}"
	GPG_KEY_ID="${fopus_config[default-key]}"


	if [[ "$UID" -eq 0 ]]; then
		echo -n "fopus: user is root. Continue? [y/N]: "
		read -r user_answer
		if [[ "$user_answer" != "y" && "$user_answer" != "Y" ]]; then
			echo "fopus: exiting"
			exit 1
		fi
	elif [[ ${#fopus_input[@]} -eq 0 ]]; then
		>&2 echo "fopus: missing file operand"
		echo "Try 'fopus --help' for more information."
		exit 1
	fi

	evaluate_options "${fopus_input[@]}"
	filter_evaluate_files

	if [[ "$root_path" =~ ^"$HOME"/?$ ]]; then
		root_path="$HOME/Backups"
	elif [[ ! -d "$root_path" ]]; then
		>&2 echo "fopus: "$root_path": No such directory"
		exit 1
	elif [[ ! "$root_path" =~ ^"$HOME"/* ]]; then
		>&2 echo "fopus: "$root_path": Permission denied"
		exit 1
	fi
	root_path=${root_path%/}

	i=1
	N="${#list_clean[@]}"
	while [[ $i -le $N ]]; do
		echo ""
		echo "fopus: "${list_clean[$i-1]}" ("$i"/"$N")"
		fopus_backup_main "${list_clean[$i-1]}"

		i=$[$i+1]
	done

	exit 0
}

evaluate_options()
{
	local list_args=("$@")

	local i=0
	local N=${#list_args[@]}
	local destroy_keep="false"

	while [[ $i -lt $N && "${list_args[$i]}" != "--" ]]; do
		case "${list_args[$i]}" in
			--destroy)
				if [[ "$destroy_keep" == "false" ]]; then
					fopus_config[destroy]="true"
					destroy_keep="true"
				fi ;;

			--keep)
				if [[ "$destroy_keep" == "false" ]]; then
					fopus_config[destroy]="false"
					destroy_keep="true"
				fi ;;

			--no-split)
				fopus_config[min-size]="-1" ;;

			*)
				>&2 echo "fopus: "${list_args["$i"]}": invalid option"
				exit 1 ;;
		esac
		i=$[$i+1]
	done

	i=$[$i+1]
	while [[ $i -lt $N ]]; do
		list_files+=( "${list_args["$i"]}" )
		i=$[$i+1]
	done
}

filter_evaluate_files()
{
	local file=""
	local i=""


	for i in ${!list_files[@]}; do
		cd "$origins"
		file="${list_files[$i]}"

		if [[ ! -e "$file" ]]; then
			>&2 echo "fopus: "$file": No such file or directory"
			continue
		elif [[ "$file" =~ ^"$HOME"/?$ ]]; then
			>&2 echo "fopus: "$file": Invalid file operand"
			continue
		fi

		if [[ -d "$file" ]]; then
			cd "$file" || exit 1
			file=$(pwd -P)
			cd ..
		else
			file="$(cd "$(dirname "$file")" && pwd -P)/$(basename "$file")"
		fi

		if [[ ! "$file" =~ ^"$HOME"/* ]]; then
			>&2 echo "fopus: "$file": Permission denied"
			continue
		fi

		echo "fopus: $(du -sh "$file")"
		list_clean+=("$file")
	done

	return 0
}

fopus_backup_main()
{
	TARGET_DIR="$1"
	perprefix="dir"

	cd "$HOME" || exit 1

	BACKUP_DIR=$(basename "$TARGET_DIR")
	BACKUP_DIR=${BACKUP_DIR// /_}

	if [[ -d "$TARGET_DIR" ]]; then
		perprefix="dir"
	else
		perprefix="file"
	fi
	FILE_NAME="$perprefix-$BACKUP_DIR.tar.xz"

	dir_hash=$(echo "$TARGET_DIR" | "$sha1sum_tool")
	BACKUP_DIR_HASH="$BACKUP_DIR-${dir_hash:0:7}"

	user_answer=""
	if [[ -e "$root_path/bak_$DATE/$BACKUP_DIR_HASH" ]]; then
		echo -n "Backup 'bak_$DATE/$BACKUP_DIR_HASH' exists. Overwrite? [y/N]: "
		read -r user_answer

		if [[ "$user_answer" == "y" || "$user_answer" == "Y" ]]; then
			echo -n "This is a backup! Really overwrite? [y/N]: "
			read -r user_answer
		else
			echo "fopus: aborting"
			return 1
		fi

		if [[ "$user_answer" == "y" || "$user_answer" == "Y" ]]; then
			rm -rf "$root_path/bak_$DATE/$BACKUP_DIR_HASH"
		else
			echo "fopus: aborting"
			return 1
		fi
	fi

	# show backup details
	echo "Source $TARGET_DIR"
	echo "Backup $root_path/bak_$DATE/$BACKUP_DIR_HASH"
	if [[ -n "$GPG_KEY_ID" ]]; then
		echo "GPG key to sign with $GPG_KEY_ID"
	else
		echo "No GPG key to sign with: gpg will use the first key found in the secret keyring"
	fi
	du -sh "$TARGET_DIR"

	echo "fopus: start backup file"
	mkdir -p "$root_path/bak_$DATE/$BACKUP_DIR_HASH" || exit 1
	cd "$root_path/bak_$DATE/$BACKUP_DIR_HASH" || exit 1


	# compress
	echo "fopus: compression"
	tar -I "${fopus_config[compress-algo]}" -cvpf "$FILE_NAME" -- "$TARGET_DIR" > "list_$perprefix-$BACKUP_DIR"

	# test compression
	echo "fopus: test compression"
	xz -tv -- "$FILE_NAME"
	if [[ "$?" -ne 0 ]]; then return 1; fi

	# encrypt
	echo "fopus: encrypt"
	gpg_command=( gpg -o "$FILE_NAME.enc" )
	if [[ -n "$GPG_KEY_ID" ]]; then
		gpg_command+=( -u "$GPG_KEY_ID" )
	fi
	gpg_command+=( -s -c -z 0 "$FILE_NAME" )
	if ! "${gpg_command[@]}"; then return 1; fi
	if [[ "${fopus_config[destroy]}" == "true" ]]; then
		rm -f "$FILE_NAME"
		echo "fopus: removed $FILE_NAME"
	fi

	# split
	echo "fopus: split"
	split_size=${fopus_config[min-size]}
	file_size=$(stat -c %s "$FILE_NAME.enc")
	if [[ "${fopus_config[min-size]}" != "-1" && \
			"$file_size" -gt "$split_size" ]]; then
		split --verbose -b "$split_size" "$FILE_NAME.enc" "$FILE_NAME.enc_"
	else
		echo "Not necessary."
	fi

	# hash
	echo "fopus: hashes"
	cd ..
	find "$BACKUP_DIR_HASH/" -type f -exec "$sha1sum_tool" {} \; >> SHA1SUMS
	find "$BACKUP_DIR_HASH/" -type f -exec md5sum {} \; >> MD5SUMS

	# file permission
	echo "fopus: file permission"
	chmod 700 "$BACKUP_DIR_HASH/"
	find "$BACKUP_DIR_HASH/" -type f -exec chmod 0600 {} \;
	find "$BACKUP_DIR_HASH/" -type d -exec chmod 0700 {} \;

	return 0
}


check_requirements

user_input="$1"
if [[ "$user_input" == "--install" || "$user_input" == "--uninstall" || \
		"$user_input" == "--update" ]]; then
	if [[ "$UID" != 0 ]]; then
		>&2 echo "fopus: permission denied"
		exit 1
	fi
elif [[ -z "$user_input" ]]; then
	>&2 echo "fopus: missing file operand"
	echo "Try 'fopus --help' for more information."
	exit 1
fi

case "$user_input" in
	--install)
		install_fopus ;;

	--uninstall)
		uninstall_fopus ;;

	--update)
		update_fopus "${@:2}" ;;

	--config)
		config_fopus "${@:2}" ;;

	--help)
		show_help ;;

	--version)
		show_version ;;

	--dir|--)
		fopus_main "${@:2}" ;;

	--*)
		>&2 echo "fopus: invalid option"
		echo "Try 'fopus --help' for more information."
		exit 1 ;;

	*)
		fopus_main "${@:1}" ;;
esac

exit 0
