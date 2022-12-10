#!/bin/bash

# MIT License
#
# Copyright (c) 2019-2022 Guilherme Tadashi Maeoka
# fopus: command-line tool to archive, compress, encrypt and split.
# <https://github.com/guimspace/fopus>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set +o allexport
version=1.6.1

if [[ "$UID" -lt 1000 ]]; then
	exit 1
fi

typeset -A fopus_config
fopus_config=(
    [max-size]="1073741824"
	[root-path]="$HOME/Backups/"
	[group-by-name]="false"
	[one]="false"
)

DATE=$(date +%Y-%m-%d)
DRY_RUN=false

check_requirements()
{
	local list_packages=(age tar xz md5sum shasum)
	local i=""

	for i in ${!list_packages[*]}; do
		if ! command -v "${list_packages[$i]}" &> /dev/null; then
			>&2 echo "fopus: ${list_packages[$i]} not found"
			exit 1
		fi
	done


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

show_help()
{
	echo "Usage: fopus [OPTION]... [FILE]..."
	echo "Archive, compress, encrypt and split (aces) the FILE(s)."
	echo ""
	echo "Commands:"
	echo ""
	echo -e "  --help\t\tdisplay this short help"
	echo -e "  --version\t\tdisplay the version number"
	echo ""
	echo "Options:"
	echo ""
	echo -e "  --no-split\t\tskip split process"
	echo -e "  --one\t\tall-in-one"
	echo -e "  --group-by-name\t\tgroup backups by file/date instead of date/name"
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

fopus_main()
{
	local list_args=("$@")

	local i=""
	local N=""
	declare -a list_files
	declare -a list_clean

	origins_path="$(pwd -P)"

	if [[ ${#list_args[@]} -eq 0 ]]; then
		>&2 echo "fopus: missing file operand"
		echo "Try 'fopus --help' for more information."
		exit 1
	fi

	evaluate_options "${list_args[@]}"
	filter_evaluate_files

	root_path="${fopus_config[root-path]}"

	if [[ "$root_path" =~ ^"$HOME"/?$ ]]; then
		root_path="$HOME/Backups"
	fi

	if [[ ! -d "$root_path" ]]; then
		>&2 echo "fopus: $root_path: No such directory"
		exit 1
	elif [[ ! -w "$root_path" ]]; then
		>&2 echo "fopus: $root_path: Permission denied"
		exit 1
	fi

	root_path=${root_path%/}

	if [[ "${fopus_config[one]}" == "true" ]]; then
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

	while [[ $i -lt $N && "${list_args[$i]}" != "--" ]]; do
		case "${list_args[$i]}" in
			--dry-run)
				DRY_RUN=true ;;

			--group-by-name)
				fopus_config[group-by-name]="true" ;;

			--one)
				fopus_config[one]="true" ;;

			--no-split)
				fopus_config[max-size]="-1" ;;

			--output)
				i=$((i+1))
				if [[ ! -d "${list_args[$i]}" ]]; then
					>&2 echo "fopus: ${list_args["$i"]}: invalid argument"
					exit 1
				fi
				fopus_config[root-path]="${list_args[$i]}" ;;

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

	if [[ "${fopus_config[one]}" == "true" ]]; then
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
	local FILE_EXTENSION=""
	local MIME_TYPE=""
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

	backup_name=$(basename -- "$TARGET_FILE")
	backup_name=${backup_name// /_}

	if [[ -d "$TARGET_FILE" ]]; then
		perprefix="dir"
		archive_name="${perprefix}_${backup_name}.tar.xz"
	else
		perprefix="file"
		if [[ "$backup_name" =~ \.[:alnum:]+$ ]]; then
			FILE_EXTENSION="${backup_name##*.}"
		fi
		MIME_TYPE=$(file --mime-type -b "$TARGET_FILE")
		if [[ "$MIME_TYPE" == "application/x-xz" || "$FILE_EXTENSION" == "xz" ]]; then
			archive_name="${perprefix}_${backup_name}"
		elif [[ "$MIME_TYPE" == "application/x-tar" || "$FILE_EXTENSION" == "tar" ]]; then
			archive_name="${perprefix}_${backup_name}.xz"
		else
			archive_name="${perprefix}_${backup_name}.tar.xz"
		fi
	fi

	hash_value=$(echo "$TARGET_FILE" | "$sha1sum_tool")
	backup_name_hash="$backup_name-${hash_value:0:7}"

	if [[ "${fopus_config[group-by-name]}" == "true" ]]; then
		bak_dir_parent="$backup_name_hash"
		bak_dir_child="bak_$DATE"
	else
		bak_dir_parent="bak_$DATE"
		bak_dir_child="$backup_name_hash"
	fi


	cd "$HOME" || exit 1

	if [[ -e "$root_path/$bak_dir_parent/$bak_dir_child" ]]; then
		>&2 echo "fopus: cannot create backup: Backup exists"
		return 0
	fi

	# show backup details
	echo "Source $TARGET_FILE"
	if [[ "${fopus_config[one]}" == "true" ]]; then
		i=1
		N="${#LIST_FILES[@]}"
		while [[ $i -lt $N ]]; do
			echo "       ${LIST_FILES[$i]}"
			i=$((i+1))
		done
	fi
	echo "Backup $root_path/$bak_dir_parent/$bak_dir_child"

	du -sh "${LIST_FILES[@]}"

	echo "fopus: start backup file"
	if [[ "$DRY_RUN" = false ]]; then
		mkdir -p "$root_path/$bak_dir_parent/$bak_dir_child" || exit 1
		cd "$root_path/$bak_dir_parent/$bak_dir_child" || exit 1
	fi


	# compress
	echo "fopus: archive and compress"
	if [[ "$MIME_TYPE" == "application/x-xz" || "$FILE_EXTENSION" == "xz" ]]; then
		echo "Skip."
		if [[ "$DRY_RUN" = false ]]; then
			cp "${LIST_FILES[@]}" "$archive_name"
		fi
	elif [[ "$MIME_TYPE" == "application/x-tar" || "$FILE_EXTENSION" == "tar" ]]; then
		echo "Compress only."
		if [[ "$DRY_RUN" = false ]]; then
			cat "${LIST_FILES[@]}" | xz --threads=0 -z -vv -k - > "$archive_name"
		fi
	elif [[ "$DRY_RUN" = false ]]; then
		tar -cvf - -- "${LIST_FILES[@]}" 2> "list_${perprefix}_${backup_name}" | xz --threads=0 -z -vv - > "$archive_name"
	fi

	# encrypt
	if [[ "$DRY_RUN" = false ]]; then
		if ! age --encrypt --passphrase "$archive_name" > "$archive_name.age"; then
			return 1
		fi
	fi

	# split
	echo "fopus: split"
	if ! fopus_split_part "$archive_name"; then
		return 1
	fi

	# hash and file permission
	"$DRY_RUN" || cd ..
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
	if [[ "$DRY_RUN" = false ]]; then
		(find "$bak_dir_child/" -type f -exec "$sha1sum_tool" {} \; >> SHA1SUMS)
		(find "$bak_dir_child/" -type f -exec md5sum {} \; >> MD5SUMS)
	fi

	# file permission
	echo "fopus: file permission"
	"$DRY_RUN" && return 0

	if ! chmod 700 "$bak_dir_child/"; then
		return 1
	fi
	(find "$bak_dir_child/" -type f -exec chmod 600 {} \;)
	(find "$bak_dir_child/" -type d -exec chmod 700 {} \;)

	return 0
}

fopus_split_part()
{
	local size_value=""
	local max_size_value=""
	local archive_name="$1"

	max_size_value=${fopus_config[max-size]}
	if [[ "$DRY_RUN" = false ]]; then
		size_value=$(stat -c %s "$archive_name.age")
	fi

	if [[ "${fopus_config[max-size]}" != "-1" && \
			"$size_value" -gt "$max_size_value" ]]; then
		"$DRY_RUN" && return 0

		if ! split --verbose -b "$max_size_value" \
			"$archive_name.age" "$archive_name.age_"; then
				return 1
		fi
	else
		echo "Not necessary."
	fi

	return 0
}


check_requirements

user_option="$1"
if [[ -z "$user_option" ]]; then
	>&2 echo "fopus: missing file operand"
	echo "Try 'fopus --help' for more information."
	exit 1
fi

case "$user_option" in
	--help)
		show_help ;;

	--version)
		echo "v$version" ;;

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
