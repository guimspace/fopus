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

set +o allexport
version=1.5.3

if [[ "$UID" == 0 ]]; then
	USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
	USER_HOME="$HOME"
fi

typeset -A fopus_config
fopus_config=(
    [max-size]="1073741824"
	[default-key]=""
	[root-path]="$USER_HOME/Backups/"
	[group-by]="date"
	[compact]="false"
	[test-compression]="true"
	[test-encryption]="true"
	[test-split]="true"
)

DATE=$(date +%Y-%m-%d)
CONFIG_PATH_DIR="$USER_HOME/.config/fopus"
DATA_PATH_DIR="$USER_HOME/.local/share/fopus"

# master
EXEC_NAME="fopus"
DL_EXE_NAME="fopus.sh"
DL_SIG_NAME="fopus.sh.sig"
REMOTE_URL_EXE="https://github.com/guimspace/fopus/releases/latest/download/$DL_EXE_NAME"
REMOTE_URL_SIG="https://github.com/guimspace/fopus/releases/latest/download/$DL_SIG_NAME"
CONFIG_PATH_FILE="$CONFIG_PATH_DIR/fopus.conf"

REMOTE_GPG_KEY="https://raw.githubusercontent.com/guimspace/fopus/master/gnupg/key.asc"

# beta
# EXEC_NAME="fopus-beta"
# REMOTE_URL="https://raw.githubusercontent.com/guimspace/fopus/beta/src/fopus.sh"
# CONFIG_PATH_FILE="$CONFIG_PATH_DIR/fopus-beta.conf"


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
	echo -e "  --config\t\tedit configuration"
	echo -e "  --update\t\tupdate fopus"
	echo -e "  --install\t\tinstall fopus"
	echo -e "  --uninstall\t\tuninstall fopus"
	echo -e "  --help\t\tdisplay this short help"
	echo -e "  --version\t\tdisplay the version number"
	echo ""
	echo "Options:"
	echo ""
	echo -e "  --no-split\t\tskip split process"
	echo -e "  --compact\t\tbackup several sources in one archive"
	echo -e "  --group-by\t\torganize backups by date/file or vice versa"
	echo ""
	echo "To aces a file whose name starts with a '-', for example '-foo',"
	echo "use one of these commands:"
	echo "  fopus -- -foo"
	echo ""
	echo "  fopus ./-foo"
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

	if ! cp "$origin_path" "/usr/local/bin/$EXEC_NAME"; then
		exit 1
	fi

	if ! chown "$USER:$(id -gn "$USER")" "/usr/local/bin/$EXEC_NAME"; then
		exit 1
	fi

	if ! chmod a+rx "/usr/local/bin/$EXEC_NAME"; then
		exit 1
	fi

	echo "fopus is installed."
	exit 0
}

uninstall_fopus()
{
	if ! rm -f "/usr/local/bin/$EXEC_NAME"; then
		exit 1
	fi

	echo "fopus is uninstalled."
	exit 0
}

update_fopus()
{
	local option="$1"
	local local_hashsum=""
	local remote_hashsum=""

	if [[ ! -f "/usr/local/bin/$EXEC_NAME" ]]; then
		>&2 echo "fopus: fopus is not installed"
		exit 1
	fi

	if ! mkdir -p "/tmp/fopus/"; then
		exit 1
	fi

	if [[ -f "/tmp/fopus/$DL_EXE_NAME" ]]; then
		rm -f "/tmp/fopus/$DL_EXE_NAME"
	fi

	if [[ -f "/tmp/fopus/$DL_SIG_NAME" ]]; then
		rm -f "/tmp/fopus/$DL_SIG_NAME"
	fi

	curl -sf -L --connect-timeout 7 -o "/tmp/fopus/$DL_EXE_NAME" "$REMOTE_URL_EXE"

	if [[ ! -f "/tmp/fopus/$DL_EXE_NAME" ]]; then
		>&2 echo "fopus: update: download failed"
		exit 1
	fi

	curl -sf -L --connect-timeout 7 -o "/tmp/fopus/$DL_SIG_NAME" "$REMOTE_URL_SIG"
	if [[ ! -f "/tmp/fopus/$DL_SIG_NAME" ]]; then
		>&2 echo "fopus: update: download failed"
		exit 1
	fi

	mkdir -p "$DATA_PATH_DIR"
	curl -s --connect-timeout 7 "$REMOTE_GPG_KEY" | gpg --no-default-keyring --keyring "$DATA_PATH_DIR/keyring.gpg" --import - 2> /dev/null

	gpg --no-default-keyring --keyring "$DATA_PATH_DIR/keyring.gpg" --trust-model always --verify "/tmp/fopus/$DL_SIG_NAME" "/tmp/fopus/$DL_EXE_NAME" 2> /dev/null
	if [[ "$?" -ne 0 ]]; then
		>&2 echo "fopus: update: couldn't verify file integrity"
		exit 1
	fi

	remote_hashsum=$($sha512sum_tool "/tmp/fopus/$DL_EXE_NAME" | cut -d " " -f 1)
	local_hashsum=$($sha512sum_tool "/usr/local/bin/$EXEC_NAME" | cut -d " " -f 1)

	if [[ "$local_hashsum" == "$remote_hashsum" ]]; then
		echo "fopus is up-to-date"
		exit 0
	fi

	echo "Updating..."

	if ! chown "$USER:$(id -gn "$USER")" "/tmp/fopus/$DL_EXE_NAME"; then
		exit 1
	fi

	if ! chmod 0755 "/tmp/fopus/$DL_EXE_NAME"; then
		exit 1
	fi

	if ! cp "/tmp/fopus/$DL_EXE_NAME" "/usr/local/bin/$EXEC_NAME"; then
		exit 1
	fi

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
	local list_options=( "default-key" "root-path" "max-size" "group-by" "compact" )

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
			continue
		fi

		if [[ "${fopus_config[$var]}" == "true" ]]; then
			echo "$var" >> "$CONFIG_PATH_FILE"
		elif [[ "${fopus_config[$var]}" != "false" && \
					-n ${fopus_config[$var]} ]]; then
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

		root-path)
			if [[ ! -d "$conf_value" ]]; then
				>&2 echo "fopus: invalid operand"
				exit 1
			elif [[ ! -w "$conf_value" ]]; then
				>&2 echo "fopus: permission denied"
				exit 1
			else
				cd "$(dirname "$conf_value")" || exit 1
				conf_value="$(pwd -P)/$(basename "$conf_value")/"
			fi

			fopus_config[root-path]="$conf_value" ;;

		group-by)
			if [[ "$conf_value" == "file" || "$conf_value" == "date" ]]; then
				fopus_config[group-by]="$conf_value"
			else
				>&2 echo "fopus: config: invalid arg"
				exit 1
			fi ;;

		max-size)
			if [[ "$conf_value" == "0" ]]; then
				conf_value=""
			fi

			fopus_config[max-size]="$conf_value" ;;

		compact)
			if [[ "$conf_value" == "true" || "$conf_value" == "false" ]]; then
				fopus_config[compact]="$conf_value"
			else
				>&2 echo "fopus: config: invalid arg"
				exit 1
			fi ;;

		*)
			echo "Syntax: fopus --config [OPTION] [ARG]"
			echo ""
			echo "Options:"
			echo ""
			echo -e "  root-path DIR\t\tset name of root directory to DIR"
			echo -e "  max-size SIZE\t\tsplit files larger than SIZE bytes"
			echo -e "  default-key NAME\tuse NAME as the default key to sign with"
			echo -e "  group-by ARG\t\tset how to organize backups"
			echo -e "  compact BOOL\t\tbackup several sources in one archive"
			echo ""
			echo "For more information visit https://github.com/guimspace/fopus."
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

	root_path="${fopus_config[root-path]}"

	if [[ "$root_path" =~ ^"$USER_HOME"/?$ ]]; then
		root_path="$USER_HOME/Backups"
	fi

	if [[ ! -d "$root_path" ]]; then
		>&2 echo "fopus: $root_path: No such directory"
		exit 1
	elif [[ ! -w "$root_path" ]]; then
		>&2 echo "fopus: $root_path: Permission denied"
		exit 1
	fi

	root_path=${root_path%/}

	if [[ "${fopus_config[compact]}" == "true" ]]; then
		echo ""
		fopus_backup_main "${list_clean[@]}"
	else
		i=1
		N="${#list_clean[@]}"
		while [[ $i -le $N ]]; do
			echo ""
			echo "fopus: ${list_clean[$i-1]} ($i/$N)"
			fopus_backup_main "${list_clean[$i-1]}"

			i=$((i+1))
		done
	fi

	exit 0
}

evaluate_options()
{
	local list_args=("$@")

	local i=0
	local N=${#list_args[@]}
	local file_date="false"
	local tmp_value=""

	while [[ $i -lt $N && "${list_args[$i]}" != "--" ]]; do
		case "${list_args[$i]}" in
			--gpg-key)
				i=$((i+1))
				fopus_config[default-key]="${list_args[i]}" ;;

			--group-by)
				i=$((i+1))
				if [[ "${list_args[$i]}" == "date" ]]; then
					tmp_value="date"
				elif [[ "${list_args[$i]}" == "file" ]]; then
					tmp_value="file"
				else
					>&2 echo "fopus: ${list_args["$i"]}: invalid argument"
					exit 1
				fi

				if [[ "$file_date" == "false" ]]; then
					fopus_config[group-by]="$tmp_value"
					file_date="true"
				fi ;;

			--compact)
				fopus_config[compact]="true" ;;

			--no-split)
				fopus_config[max-size]="-1" ;;

			--output)
				i=$((i+1))
				if [[ ! -d "${list_args[$i]}" ]]; then
					>&2 echo "fopus: ${list_args["$i"]}: invalid argument"
					exit 1
				fi
				fopus_config[root-path]="${list_args[$i]}" ;;

			-tc)
				fopus_config[test-compression]="false" ;;

			-te)
				fopus_config[test-encryption]="false" ;;

			-ts)
				fopus_config[test-split]="false" ;;

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
	local command_continue=""

	if [[ "${fopus_config[compact]}" == "true" ]]; then
		command_continue=( exit 1 )
	else
		command_continue=( continue )
	fi


	for i in "${!list_files[@]}"; do
		cd "$origins_path" || exit 1
		file="${list_files[$i]}"

		if [[ ! -e "$file" ]]; then
			>&2 echo "fopus: $file: No such file or directory"
			"${command_continue[@]}"
		elif [[ ! -r "$file" ]]; then
			>&2 echo "fopus: $file: Permission denied"
			"${command_continue[@]}"
		fi

		if [[ -d "$file" ]]; then
			cd "$file" || exit 1
			file=$(pwd -P)
			cd ..
		else
			file="$(cd "$(dirname "$file")" && pwd -P)/$(basename "$file")"
		fi

		echo "fopus: $(du -sh "$file")"
		list_clean+=("$file")
	done

	return 0
}

fopus_backup_main()
{
	local TARGET_FILE="$1"
	local LIST_FILES=("$@")

	local backup_name=""
	local backup_name_hash=""
	local archive_name=""
	local bak_dir_parent=""
	local bak_dir_child=""

	local i=""
	local N=""
	local perprefix=""
	local hash_value=""

	backup_name=$(basename "$TARGET_FILE")
	backup_name=${backup_name// /_}

	if [[ -d "$TARGET_FILE" ]]; then
		perprefix="dir"
	else
		perprefix="file"
	fi

	archive_name="${perprefix}_${backup_name}.tar.xz"
	hash_value=$(echo "$TARGET_FILE" | "$sha1sum_tool")
	backup_name_hash="$backup_name-${hash_value:0:7}"

	if [[ "${fopus_config[group-by]}" == "file" ]]; then
		bak_dir_parent="$backup_name_hash"
		bak_dir_child="bak_$DATE"
	else
		bak_dir_parent="bak_$DATE"
		bak_dir_child="$backup_name_hash"
	fi


	cd "$USER_HOME" || exit 1

	# test overwrite
	if ! fopus_overwrite_part "$bak_dir_parent" "$bak_dir_child"; then
		return
	fi

	# show backup details
	echo "Source $TARGET_FILE"
	if [[ "${fopus_config[compact]}" == "true" ]]; then
		i=1
		N="${#LIST_FILES[@]}"
		while [[ $i -lt $N ]]; do
			echo "       ${LIST_FILES[$i]}"
			i=$((i+1))
		done
	fi
	echo "Backup $root_path/$bak_dir_parent/$bak_dir_child"
	if [[ -n "$gpg_key_id" ]]; then
		echo "GPG key to sign with $gpg_key_id"
	else
		echo "No GPG key to sign with: gpg will use the first key found in the secret keyring"
	fi
	du -sh "${LIST_FILES[@]}"

	echo "fopus: start backup file"
	mkdir -p "$root_path/$bak_dir_parent/$bak_dir_child" || exit 1
	cd "$root_path/$bak_dir_parent/$bak_dir_child" || exit 1


	# compress
	echo "fopus: archive and compress"
	tar -cvpf - -- "${LIST_FILES[@]}" 2> "list_${perprefix}_${backup_name}" | xz --threads=0 -z -vv - > "$archive_name"

	# test compression
	echo "fopus: test compression"
	if [[ "${fopus_config[test-compression]}" == "true" ]]; then
		if ! xz -tv -- "$archive_name"; then
			return 1;
		fi
	else
		echo "Skip."
	fi

	# encrypt
	echo "fopus: encrypt"
	if ! fopus_encryption_part "$archive_name"; then
		return 1
	fi

	# verify encrypt
	echo "fopus: verify encryption"
	if [[ "${fopus_config[test-encryption]}" == "true" ]]; then
		if ! fopus_verify_encryption_part "$archive_name"; then
			return 1
		fi
	else
		echo "Skip."
	fi

	# split
	echo "fopus: split"
	if ! fopus_split_part "$archive_name"; then
		return 1
	fi

	# test split
	if ! fopus_test_split_part "$archive_name"; then
		return 1
	fi

	# hash and file permission
	cd ..
	if ! fopus_hash_permission_part "$bak_dir_child"; then
		return 1
	fi

	return 0
}

fopus_hash_permission_part()
{
	local bak_dir_child="$1"

	# hashes
	echo "fopus: hashes"
	(find "$bak_dir_child/" -type f -exec "$sha1sum_tool" {} \; >> SHA1SUMS)
	(find "$bak_dir_child/" -type f -exec md5sum {} \; >> MD5SUMS)

	# file permission
	echo "fopus: file permission"
	if ! chmod 700 "$bak_dir_child/"; then
		return 1
	fi
	(find "$bak_dir_child/" -type f -exec chmod 600 {} \;)
	(find "$bak_dir_child/" -type d -exec chmod 700 {} \;)

	return 0
}

fopus_overwrite_part()
{
	local bak_dir_parent="$1"
	bak_dir_child="$2"

	local c=""
	local suf=""
	local user_answer=""

	if [[ ! -e "$root_path/$bak_dir_parent/$bak_dir_child" ]]; then
		return 0
	fi

	echo "Backup '$bak_dir_parent/$bak_dir_child' exists."

	c=0
	for suf in $(seq -f "%03g" 1 999); do
		c=$((c+1))
		if [[ ! -e "$root_path/$bak_dir_parent/$bak_dir_child""_$suf" ]]; then
			break
		fi
	done

	if [[ -e "$root_path/$bak_dir_parent/$bak_dir_child""_001" ]]; then
		echo "$c level(s) of rename exist."
	fi

	echo -e "y - yes"
	echo -e "n - no, abort"
	echo -e "r - rename"
	echo -e "e - exit fopus"
	echo ""
	echo -n "Overwrite [y,n,r,e]?: "
	read -r user_answer

	if [[ "$user_answer" == "e" ]]; then
		echo "fopus: exiting"
		exit 1
	elif [[ "$user_answer" == "r" ]]; then
		bak_dir_child="$bak_dir_child"_"$suf"
		echo "Backup renamed to '$bak_dir_child'."
	elif [[ "$user_answer" == "y" ]]; then
		echo -n "This is a backup! Really overwrite? [y/N]: "
		read -r user_answer

		if [[ "$user_answer" == "y" ]]; then
			rm -rf "${root_path:?}/$bak_dir_parent/$bak_dir_child"
		else
			echo "fopus: aborting"
			return 1
		fi
	else
		echo "fopus: aborting"
		return 1
	fi

	return 0
}

fopus_encryption_part()
{
	local gpg_tool=( )
	local archive_name="$1"
	local user_option_abc=""
	local check=""

	gpg_tool=( gpg -o "$archive_name.enc" )

	if [[ -n "$gpg_key_id" ]]; then
		gpg_tool+=( -u "$gpg_key_id" )
	fi

	gpg_tool+=( -s -c -z 0 "$archive_name" )

	check="false"
	while [[ "$check" == "false" ]]; do
		if ! "${gpg_tool[@]}"; then
			echo "Encryption failed."
			echo -e "e - exit fopus"
			echo -e "r - retry encryption"
			echo -e "s - skip encryption"
			echo ""
			echo -n "[e,r,s]? "

			read -r user_option_abc

			case "$user_option_abc" in
				e)
					return 1 ;;

				s)
					check="true" ;;

				r)
					;;
			esac
		else
			check="true"
			break
		fi
	done

	return 0
}

fopus_verify_encryption_part()
{
	local gpg_tool=( )
	local archive_name="$1"

	gpg_tool=( gpg -o "/dev/null" -d "$archive_name.enc" )

	if ! "${gpg_tool[@]}"; then
		return 1
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

fopus_test_split_part()
{
	local first_hashsum=""
	local split_hashsum=""
	local size_value=""
	local max_size_value=""
	local archive_name="$1"

	max_size_value=${fopus_config[max-size]}
	size_value=$(stat -c %s "$archive_name.enc")

	if ! [[ "${fopus_config[max-size]}" != "-1" && \
			"$size_value" -gt "$max_size_value" ]]; then
			return 0
	fi

	echo "fopus: test split"

	first_hashsum=$($sha512sum_tool "$archive_name.enc" | cut -d " " -f 1)
	split_hashsum=$(cat "$archive_name.enc_"* | $sha512sum_tool | cut -d " " -f 1)

	if [[ "$split_hashsum" == "$first_hashsum" ]]; then
		return 0
	else
		return 1
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
