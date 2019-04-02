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

version=0.4.0

# https://unix.stackexchange.com/a/232083 for the future
# unset -v password
# set +o allexport

typeset -A fopus_config
fopus_config=(
    [max-size]="1073741824"
	[default-key]=""
	[root-path]="$HOME/Backups/"
	[compress-algo]="xz"
	[destroy]="false"
)

DATE=$(date +%Y-%m-%d)
CONFIG_PATH_DIR="$HOME/.config/fopus"
CONFIG_PATH_FILE="$CONFIG_PATH_DIR/fopus.conf"
REMOTE_URL="https://raw.githubusercontent.com/guimspace/fopus/master/src/fopus.sh"


check_requirements()
{
	local list_packages=(gpg curl tar xz md5sum shasum)
	local i=""

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
	echo "fopus v$version"
	echo "Copyright (C) 2019 Guilherme Tadashi Maeoka"
	echo "License GPLv3+: GNU GPL version 3 or later <https://www.gnu.org/licenses/>."
	echo "This is free software: you are free to change and redistribute it."
	echo "There is NO WARRANTY, to the extent permitted by law."

}

show_help()
{
	echo "Usage: fopus [OPTION]... [FILE]..."
	echo "Archive, compress, encrypt and split (aces) the FILE(s)."
	echo ""
	echo "Commands:"
	echo ""
	echo -e "  --dir\t\tarchive, compress, encrypt and split"
	echo -e "  --config\tset options"
	echo -e "  --update\tupdate fopus"
	echo -e "  --install\tinstall fopus"
	echo -e "  --uninstall\tuninstall fopus"
	echo -e "  --help\tdisplay this short help and exit"
	echo -e "  --version\tdisplay the version number and exit"
	echo ""
	echo "Options:"
	echo ""
	echo -e "  --no-split\t\t\tskip split process"
	echo -e "  --destroy\t\t\tremove compressed archive after encryption"
	echo -e "  --keep\t\t\tkeep compressed archive after encryption"
	echo ""
	echo "Note that the option 'destroy' does not securely delete the compressed archive."
	echo ""
	echo "To aces a file whose name starts with a '-', for example '-foo',"
	echo "use one of these commands:"
	echo "  fopus -- -foo"
	echo ""
	echo "  fopus ./-foo"
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
	echo ""
	echo "Report bugs, comments and suggestions to <gui.mspace@gmail.com> (in English or Portuguese)."
	echo "fopus repository: <https://github.com/guimspace/fopus>"
}

install_fopus()
{
	local origin_path=""

	if [[ ! -d "/usr/local/bin/" ]]; then
		>&2 echo "fopus: /usr/local/bin/ not found"
		exit 1
	fi

	origin_path="$(cd "$(dirname "$0")" && pwd -P)/$(basename "$0")"

	if ! cp "$origin_path" "/usr/local/bin/fopus"; then
		exit 1
	fi

	if ! chown "$USER:$(id -gn "$USER")" "/usr/local/bin/fopus"; then
		exit 1
	fi

	if ! chmod a+rx "/usr/local/bin/fopus"; then
		exit 1
	fi

	echo "fopus is installed."
	exit 0
}

uninstall_fopus()
{
	if ! rm -f "/usr/local/bin/fopus"; then
		exit 1
	fi

	echo "fopus is uninstalled."
	exit 0
}

update_fopus()
{
	local local_hashsum=""
	local remote_hashsum=""

	if [[ ! -f "/usr/local/bin/fopus" ]]; then
		>&2 echo "fopus: fopus is not installed"
		exit 1
	fi

	if ! mkdir -p "/tmp/fopus/"; then
		exit 1
	fi

	if [[ -f "/tmp/fopus/fopus" ]]; then
		rm -f "/tmp/fopus/fopus"
	fi

	curl -sf --connect-timeout 7 -o "/tmp/fopus/fopus" "$REMOTE_URL"

	if [[ ! -f "/tmp/fopus/fopus" ]]; then
		>&2 echo "fopus: update: download failed"
		exit 1
	fi

	remote_hashsum=$($sha512sum_tool "/tmp/fopus/fopus" | cut -d " " -f 1)

	local_hashsum=$($sha512sum_tool "/usr/local/bin/fopus" | cut -d " " -f 1)
	if [[ "$local_hashsum" == "$remote_hashsum" ]]; then
		echo "fopus is up-to-date"
		exit 0
	fi

	echo "Updating..."

	cp "/tmp/fopus/fopus" "/usr/local/bin/fopus"
	chown "$USER:$(id -gn "$USER")" "/usr/local/bin/fopus"
	chmod 0755 "/usr/local/bin/fopus"

	echo "fopus is up-to-date"
	exit 0
}

init_conf()
{
	if [[ "$UID" -eq 0 ]]; then
		>&2 echo "fopus: user is root: Permission denied"
		exit 1
	fi

	if [[ -f "$CONFIG_PATH_FILE" ]]; then
		return 0
	fi

	if [[ ! -d "$CONFIG_PATH_DIR" ]]; then
		if ! mkdir -p "$CONFIG_PATH_DIR"; then
			exit 1
		fi
	fi

	if ! touch "$CONFIG_PATH_FILE"; then
		exit 1
	fi

	return 0
}

read_conf()
{
	local var=""
	local value=""

	if [[ ! -f "$CONFIG_PATH_FILE" ]]; then
		init_conf
	fi

	while read -r var value; do
		if [[ -n "$var" && -n "$value" ]]; then
			fopus_config["$var"]="$value"
		elif [[ -z "$value" ]]; then
			case "$var" in
				destroy)
					fopus_config["$var"]="true"

			esac
		fi
	done < "$CONFIG_PATH_FILE"
}

save_conf()
{
	if [[ ! -f "$CONFIG_PATH_FILE" ]]; then
		init_conf
	fi

	local opt=""
	local var=""
	local check="false"
	local list_options=( "default-key" "compress-algo" "root-path" \
							"max-size" "destroy" )

	echo "# fopus" > "$CONFIG_PATH_FILE"
	for var in ${!fopus_config[*]}; do
		check="false"

		for opt in ${!list_options[*]}; do
			if [[ "$var" == "${list_options[$opt]}" ]]; then
				check="true"
				break
			fi
		done

		if [[ "$check" == "false" ]]; then
			>&2 echo "fopus: $var: invalid option"
			continue
		fi

		if [[ "${fopus_config[$var]}" == "true" || \
				"${fopus_config[$var]}" == "false" ]]; then
			echo "$var" >> "$CONFIG_PATH_FILE"
		elif [[ -n ${fopus_config[$var]} ]]; then
			echo "$var ${fopus_config[$var]}" >> "$CONFIG_PATH_FILE"
		fi
	done
}

config_fopus()
{
	read_conf

	local conf_option="$1"
	local conf_value="$2"

	case "$conf_option" in
		default-key)
			fopus_config[default-key]="$conf_value" ;;

		compress-algo)
			if [[ -z "$conf_value" || "$conf_value" == "1" ]]; then
				conf_value="xz"
			elif [[ "$conf_value" == "2" ]]; then
				conf_value="pxz"
			else
				>&2 echo "fopus: invalid operand"
				exit 1
			fi

			fopus_config[compress-algo]="$conf_value" ;;

		root-path)
			if [[ "$conf_value" =~ ^"$HOME"/?$ ]]; then
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

		max-size)
			if [[ "$conf_value" == "0" ]]; then
				conf_value=""
			fi

			fopus_config[max-size]="$conf_value" ;;

		destroy)
			if [[ "$conf_value" == "true" || "$conf_value" == "false" ]]; then
				fopus_config[destroy]="$conf_value"
			else
				>&2 echo "fopus: config: invalid arg"
				exit 1
			fi ;;

		*)
			echo "Usage: fopus --config [OPTION] [ARG]"
			echo ""
			echo "Options:"
			echo ""
			echo -e "  default-key NAME\tuse NAME as the default key to sign with"
			echo -e "  max-size SIZE\t\tput SIZE bytes per output file; 0 and blank defaults to 1073741824"
			echo -e "  compress-algo n\t\tuse compress algorithm n; default is 1 which is xz; use 2 to use pxz"
			echo -e "  root-path DIR\t\tput backups in DIR; blank defaults to '\$HOME/Backups'"
			echo -e "  destroy BOOL\t\tremove compressed archive after encryption"
			exit 0 ;;
	esac

	save_conf
	exit 0
}

fopus_main()
{
	read_conf
	local list_args=("$@")

	local i=""
	local N=""
	declare -a list_files
	declare -a list_clean

	origins_path="$(pwd -P)"
	root_path="${fopus_config[root-path]}"
	gpg_key_id="${fopus_config[default-key]}"


	user_answer=""
	if [[ "$UID" -eq 0 ]]; then
		echo -n "fopus: user is root. Continue? [y/N]: "
		read -r user_answer
		if [[ "$user_answer" != "y" && "$user_answer" != "Y" ]]; then
			echo "fopus: exiting"
			exit 1
		fi
	elif [[ ${#list_args[@]} -eq 0 ]]; then
		>&2 echo "fopus: missing file operand"
		echo "Try 'fopus --help' for more information."
		exit 1
	fi

	evaluate_options "${list_args[@]}"
	filter_evaluate_files

	if [[ "$root_path" =~ ^"$HOME"/?$ ]]; then
		root_path="$HOME/Backups"
	elif [[ ! -d "$root_path" ]]; then
		>&2 echo "fopus: $root_path: No such directory"
		exit 1
	elif [[ ! "$root_path" =~ ^"$HOME"/* ]]; then
		>&2 echo "fopus: $root_path: Permission denied"
		exit 1
	fi
	root_path=${root_path%/}

	i=1
	N="${#list_clean[@]}"
	while [[ $i -le $N ]]; do
		echo ""
		echo "fopus: ${list_clean[$i-1]} ($i/$N)"
		fopus_backup_main "${list_clean[$i-1]}"

		i=$((i+1))
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
				fopus_config[max-size]="-1" ;;

			--)
				break ;;

			--*)
				>&2 echo "fopus: ${list_args["$i"]}: invalid option"
				echo "Try 'fopus --help' for more information."
				exit 1 ;;

			*)
				i=$((i-1))
				break ;;
		esac
		i=$((i+1))
	done

	i=$((i+1))
	while [[ $i -lt $N ]]; do
		list_files+=( "${list_args["$i"]}" )
		i=$((i+1))
	done
}

filter_evaluate_files()
{
	local i=""
	local file=""


	for i in "${!list_files[@]}"; do
		cd "$origins_path" || exit 1
		file="${list_files[$i]}"

		if [[ ! -e "$file" ]]; then
			>&2 echo "fopus: $file: No such file or directory"
			continue
		elif [[ "$file" =~ ^"$HOME"/?$ ]]; then
			>&2 echo "fopus: $file: Invalid file operand"
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
			>&2 echo "fopus: $file: Permission denied"
			continue
		fi

		echo "fopus: $(du -sh "$file")"
		list_clean+=("$file")
	done

	return 0
}

fopus_backup_main()
{
	local TARGET_FILE="$1"

	local backup_name=""
	local backup_name_hash=""
	local archive_name=""

	local perprefix=""
	local hash_value=""

	backup_name=$(basename "$TARGET_FILE")
	backup_name=${backup_name// /_}

	if [[ -d "$TARGET_FILE" ]]; then
		perprefix="dir"
	else
		perprefix="file"
	fi

	archive_name="$perprefix-$backup_name.tar.xz"
	hash_value=$(echo "$TARGET_FILE" | "$sha1sum_tool")
	backup_name_hash="$backup_name-${hash_value:0:7}"


	cd "$HOME" || exit 1

	# test overwrite
	if ! fopus_overwrite_part; then
		return
	fi

	# show backup details
	echo "Source $TARGET_FILE"
	echo "Backup $root_path/bak_$DATE/$backup_name_hash"
	if [[ -n "$gpg_key_id" ]]; then
		echo "GPG key to sign with $gpg_key_id"
	else
		echo "No GPG key to sign with: gpg will use the first key found in the secret keyring"
	fi
	du -sh "$TARGET_FILE"

	echo "fopus: start backup file"
	mkdir -p "$root_path/bak_$DATE/$backup_name_hash" || exit 1
	cd "$root_path/bak_$DATE/$backup_name_hash" || exit 1


	# compress
	echo "fopus: compression"
	tar -I "${fopus_config[compress-algo]}" -cvpf "$archive_name" -- "$TARGET_FILE" > "list_$perprefix-$backup_name"

	# test compression
	echo "fopus: test compression"
	if ! xz -tv -- "$archive_name"; then
		return 1;
	fi

	# encrypt
	echo "fopus: encrypt"
	if ! fopus_encryption_part "$archive_name"; then
		return 1
	fi

	# split
	echo "fopus: split"
	if ! fopus_split_part "$archive_name"; then
		return 1
	fi

	# hash and file permission
	cd ..
	if ! fopus_hash_permission_part "$backup_name_hash"; then
		return 1
	fi

	return 0
}

fopus_hash_permission_part()
{
	local backup_name_hash="$1"
	local find_command=""

	# hashes
	echo "fopus: hashes"
	(find "$backup_name_hash/" -type f -exec "$sha1sum_tool" {} \; >> SHA1SUMS)
	(find "$backup_name_hash/" -type f -exec md5sum {} \; >> MD5SUMS)

	# file permission
	echo "fopus: file permission"
	if ! chmod 700 "$backup_name_hash/"; then
		return 1
	fi
	(find "$backup_name_hash/" -type f -exec chmod 600 {} \;)
	(find "$backup_name_hash/" -type d -exec chmod 700 {} \;)

	return 0
}

fopus_overwrite_part()
{
	local user_answer=""

	if [[ -e "$root_path/bak_$DATE/$backup_name_hash" ]]; then
		echo -n "Backup 'bak_$DATE/$backup_name_hash' exists. Overwrite? [y/N]: "
		read -r user_answer

		if [[ "$user_answer" == "y" || "$user_answer" == "Y" ]]; then
			echo -n "This is a backup! Really overwrite? [y/N]: "
			read -r user_answer
		else
			echo "fopus: aborting"
			return 1
		fi

		if [[ "$user_answer" == "y" || "$user_answer" == "Y" ]]; then
			rm -rf "$root_path/bak_$DATE/$backup_name_hash"
		else
			echo "fopus: aborting"
			return 1
		fi
	fi

	return 0
}

fopus_encryption_part()
{
	local gpg_tool=""
	local archive_name="$1"

	gpg_tool=( gpg -o "$archive_name.enc" )

	if [[ -n "$gpg_key_id" ]]; then
		gpg_tool+=( -u "$gpg_key_id" )
	fi

	gpg_tool+=( -s -c -z 0 "$archive_name" )

	if ! "${gpg_tool[@]}"; then
		return 1
	fi

	if [[ "${fopus_config[destroy]}" == "true" ]]; then
		rm -f "$archive_name"
		echo "fopus: removed $archive_name"
	fi

	return 0
}

fopus_split_part()
{
	local size_value=""
	local max_size_value=""
	local archive_name="$1"

	max_size_value=${fopus_config[max-size]}
	size_value=$(stat -c %s "$archive_name.enc")

	if [[ "${fopus_config[max-size]}" != "-1" && \
			"$size_value" -gt "$max_size_value" ]]; then
		if ! split --verbose -b "$max_size_value" \
			"$archive_name.enc" "$archive_name.enc_"; then
				return 1
		fi
	else
		echo "Not necessary."
	fi

	return 0
}


check_requirements

user_option="$1"
if [[ "$user_option" == "--install" || "$user_option" == "--uninstall" || \
		"$user_option" == "--update" ]]; then
	if [[ "$UID" != 0 ]]; then
		>&2 echo "fopus: permission denied"
		exit 1
	fi
elif [[ -z "$user_option" ]]; then
	>&2 echo "fopus: missing file operand"
	echo "Try 'fopus --help' for more information."
	exit 1
fi

case "$user_option" in
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

	# --*)
	# 	>&2 echo "fopus: invalid option"
	# 	echo "Try 'fopus --help' for more information."
	# 	exit 1 ;;

	*)
		fopus_main "${@:1}" ;;
esac

exit 0
