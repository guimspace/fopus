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

if [[ "$UID" -lt 1000 ]]; then
	exit 1
fi

declare -r VERSION="1.6.1"

DATE=$(date +%Y-%m-%d)
declare -r DATE

DRY_RUN="false"

declare -A CONFIG=(
	[part-size]=""
	[repo-path]="$HOME/Backups/"
	[group-by-name]="false"
	[one]="false"
)

check_requirements()
{
	declare -ar apps=(age minisign tar xz md5sum shasum)
	local app=""

	for app in "${apps[@]}"; do
		if ! command -v "${app}" &> /dev/null; then
			>&2 echo "fopus: ${app} not found"
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
	echo "Usage: fopus [OPTION]... FILE..."
	echo ""
	echo "Commands:"
	echo -e "\t--help\t\t\tdisplay this short help"
	echo -e "\t--version\t\tdisplay version number"
	echo ""
	echo "Options:"
	echo -e "\t--one\t\t\tput FILEs in one backup."
	echo -e "\t--no-split\t\tdon't split backup in parts."
	echo -e "\t--split-size SIZE\tsplit backup pieces of SIZE"
	echo -e "\t--group-by-name\t\tgroup backups by file/date instead of date/name."
	echo -e "\t--output OUTPUT\t\tbackup in the directory at path OUTPUT."
}

main()
{
	declare -r ORIGIN="$(pwd -P)"
	declare -a FILES=()

	if [[ -z "$*" ]]; then
		>&2 echo "fopus: missing file operand"
		echo "Try 'fopus --help' for more information."
		exit 1
	fi

	evaluate_arguments "$@"
	declare -r DRY_RUN="$DRY_RUN"

	OUTPUT_PATH="${CONFIG[repo-path]}"
	OUTPUT_PATH=$(cd "$OUTPUT_PATH" && pwd -P)

	if [[ ! -d "$OUTPUT_PATH" ]]; then
		>&2 echo "fopus: $OUTPUT_PATH: No such directory"
		exit 1
	elif [[ "$OUTPUT_PATH" =~ ^"$HOME"/?$ ]]; then
		>&2 echo "fopus: $OUTPUT_PATH: Permission denied"
		exit 1
	elif [[ ! -w "$OUTPUT_PATH" ]]; then
		>&2 echo "fopus: $OUTPUT_PATH: Permission denied"
		exit 1
	fi

	OUTPUT_PATH=${OUTPUT_PATH%/}
	declare -r OUTPUT_PATH="$OUTPUT_PATH"

	evaluate_files

	if [[ "${CONFIG[one]}" = "true" ]]; then
		echo ""
		fopus_backup "${FILES[@]}"
	else
		declare -i i=0
		declare -ir N="${#FILES[@]}"
		local file=""
		for file in "${FILES[@]}"; do
			((i++))
			echo ""
			echo "fopus: ${FILES[$i-1]} ($i of $N)"
			fopus_backup "$file"
		done
	fi

	exit 0
}

evaluate_arguments()
{
	declare -ar ARGS=("$@")

	local -ir N=${#ARGS[@]}
	local -i i=0

	while [[ $i -lt $N && "${ARGS[$i]}" != "--" ]]; do
		case "${ARGS[$i]}" in
			"--dry-run")
				DRY_RUN="true" ;;

			"--group-by-name")
				CONFIG[group-by-name]="true" ;;

			"--one")
				CONFIG[one]="true" ;;

			"--no-split")
				if [[ -n "${CONFIG[part-size]}" ]]; then
					>&2 echo "fopus: --split-size can't be used with --no-split"
					exit 1
				fi
				CONFIG[part-size]="-1" ;;

			"--split-size")
				if [[ -n "${CONFIG[part-size]}" ]]; then
					>&2 echo "fopus: --split-size can't be used with --no-split"
					exit 1
				fi
				((i++))
				if ! split --bytes="${ARGS["$i"]}" /dev/null; then
					exit 1
				fi
				CONFIG[part-size]="${ARGS["$i"]}" ;;

			"--output")
				((i++))
				if [[ ! -d "${ARGS[$i]}" ]]; then
					>&2 echo "fopus: ${ARGS["$i"]}: No such directory"
					exit 1
				fi
				CONFIG[repo-path]="${ARGS[$i]}" ;;

			"--")
				break ;;

			"--"*)
				>&2 echo "fopus: ${ARGS["$i"]}: invalid option"
				echo "Try 'fopus --help' for more information."
				exit 1 ;;

			*)
				((i--))
				break ;;
		esac
		((i++))
	done

	if [[ -z "${CONFIG[part-size]}" ]]; then
		CONFIG[part-size]="1073741824"
	fi

	((i++))
	FILES=("${ARGS[@]:$i}")

	return 0
}

evaluate_files()
{
	local file=""

	declare -i i=0
	declare -ir N="${#FILES[@]}"

	while [[ "$i" -lt "$N" ]]; do
		file="${FILES[$i]}"
		if [[ ! -e "$file" ]]; then
			>&2 echo "fopus: $file: No such file or directory"
			exit 1
		elif [[ ! -r "$file" ]]; then
			>&2 echo "fopus: $file: Permission denied"
			exit 1
		fi

		if [[ -d "$file" ]]; then
			cd "$file" || exit 1
			file=$(pwd -P)
		else
			file="$(cd "$(dirname "$file")" && pwd -P)/$(basename "$file")"
		fi

		FILES["$i"]="$file"
		echo "fopus: $(du -shL "${file}")"
		((i++))
	done

	cd "$ORIGIN" || exit 1

	return 0
}

fopus_backup()
{
	local -r LIST_FILES=("$@")

	local BACKUP_FILE=""
	local BACKUP_PATH=""
	local BACKUP_DIR=""

	local tmp=""

	REPO_NAME=$(basename -- "${LIST_FILES[0]}")
	REPO_NAME=${REPO_NAME// /_}

	BACKUP_FILE="${REPO_NAME}.tar.xz"

	tmp=$(echo "${LIST_FILES[0]}" | "$sha1sum_tool")
	tmp="$REPO_NAME-${tmp:0:11}"

	if [[ "${CONFIG[group-by-name]}" = "true" ]]; then
		BACKUP_PATH="$OUTPUT_PATH/$tmp"
		BACKUP_DIR="backup_$DATE"
	else
		BACKUP_PATH="$OUTPUT_PATH/backup_$DATE"
		BACKUP_DIR="$tmp"
	fi

	cd "$HOME" || exit 1

	if [[ -e "$BACKUP_PATH/$BACKUP_DIR" ]]; then
		>&2 echo "fopus: cannot create backup: Backup exists"
		exit 1
	fi

	# show backup details
	echo "Source ${LIST_FILES[0]}"
	if [[ "${CONFIG[one]}" = "true" ]]; then
		declare -i i=1
		N="${#LIST_FILES[@]}"
		while [[ $i -lt $N ]]; do
			echo "       ${LIST_FILES[$i]}"
			((i++))
		done
	fi
	echo "Backup $BACKUP_PATH/$BACKUP_DIR"

	(du -shL "${LIST_FILES[@]}")

	echo "fopus: start backup file"
	if [[ "$DRY_RUN" = "false" ]]; then
		mkdir -p "$BACKUP_PATH/$BACKUP_DIR" || exit 1
		cd "$BACKUP_PATH/$BACKUP_DIR" || exit 1
	fi

	# compress
	echo "fopus: archive and compress"
	if [[ "$DRY_RUN" = "false" ]]; then
		tar -cvf - -- "${LIST_FILES[@]}" 2> "${REPO_NAME}.txt" | xz --threads=0 -z -vv - > "$BACKUP_FILE"
	fi

	# encrypt
	if [[ "$DRY_RUN" = "false" ]]; then
		if ! age --encrypt --passphrase "$BACKUP_FILE" > "$BACKUP_FILE.age"; then
			return 1
		fi
	fi

	# split
	echo "fopus: split"
	if ! split_file "$BACKUP_FILE"; then
		return 1
	fi

	# sign
	if ! sign_files; then
		return 1
	fi

	# hash and file permission
	[[ "$DRY_RUN" = "true" ]] || cd ..
	if ! hash_permission "$BACKUP_DIR"; then
		return 1
	fi

	return 0
}

split_file()
{
	if [[ "${CONFIG[part-size]}" = "-1" ]]; then
		echo "Skip."
		return 0
	fi

	local FILE_SIZE=""
	local LIMIT_SIZE=""

	if [[ "$DRY_RUN" = false ]]; then
		FILE_SIZE=$(stat -c %s "$1.age")
		LIMIT_SIZE=$(echo "${CONFIG[part-size]}" | numfmt --from=iec)

		if [[ "$FILE_SIZE" -gt "$LIMIT_SIZE" ]]; then
			# split
			if ! split --verbose --bytes="${CONFIG[part-size]}" \
				"$1.age" "$1.age_"; then
					return 1
			fi
		fi
	fi

	return 0
}

sign_files()
{
	if [[ "$DRY_RUN" = "false" ]]; then
		# hash
		echo "fopus: hashes"
		if ! "$sha256sum_tool" ./* > "SHA256SUMS"; then
			return 1
		fi
		echo "fopus: sign"
		if ! minisign -Sm "SHA256SUMS"; then
			return 1
		fi
	fi

	return 0
}

hash_permission()
{
	# hashes
	if [[ "$DRY_RUN" = "false" ]]; then
		(find "$1/" -type f -exec "$sha1sum_tool" {} \; >> SHA1SUMS)
		(find "$1/" -type f -exec md5sum {} \; >> MD5SUMS)
	fi

	# file permission
	echo "fopus: file permission"
	if [[ "$DRY_RUN" = "false" ]]; then
		if ! chmod 700 "$1/"; then
			return 1
		fi
		(find "$1/" -type f -exec chmod 600 {} \;)
		(find "$1/" -type d -exec chmod 700 {} \;)
	fi

	return 0
}

check_requirements

if [[ -z "$1" ]]; then
	>&2 echo "fopus: missing file operand"
	echo "Try 'fopus --help' for more information."
	exit 1
fi

case "$1" in
	"--help")
		show_help ;;

	"--version")
		echo "v${VERSION}" ;;

	"--")
		main "${@:2}" ;;

	*)
		main "${@:1}" ;;
esac

exit 0