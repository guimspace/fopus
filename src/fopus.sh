#!/bin/bash

# MIT License
#
# Copyright (c) 2019-2024 Guilherme Tadashi Maeoka
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

set -euo pipefail

if [[ "$UID" -lt 1000 ]]; then
	exit 1
fi

declare -r VERSION="3.1.0-rc3"

printf -v DATE "%(%Y-%m-%d)T" -1
declare -r DATE

declare -g CLEANUP_DIR=""

cleanup()
{
	trap - SIGINT SIGTERM

	declare -rg CLEANUP_DIR
	local -r target=$(realpath "$CLEANUP_DIR")

	if [[ ! -e "$target" ]]; then
		:
	elif [[ ! -d "$target" ]]; then
		:
	elif [[ "$target" =~ ^"/"$ ]]; then
		:
	else
		rm -rf "$target"
	fi

	kill -SIGINT $$
}

check_requirements()
{
	local -r apps=(tar xz realpath tr split numfmt stat basename find cat)

	local app=""
	for app in "${apps[@]}"; do
		if ! command -v "${app}" &> /dev/null; then
			>&2 echo "fopus: ${app} not found"
			exit 1
		fi
	done

	if command -v age &> /dev/null; then
		age_tool="$(command -v age)"
	else
		>&2 echo "fopus: age not found"
		exit 1
	fi
	declare -gr age_tool

	if command -v minisign &> /dev/null; then
		minisign_tool="$(command -v minisign)"
	else
		>&2 echo "fopus: minisign not found"
		exit 1
	fi
	declare -gr minisign_tool

	if command -v sha1sum &> /dev/null; then
		sha1sum_tool="$(command -v sha1sum)"
	elif command -v shasum &> /dev/null; then
		sha1sum_tool="$(command -v shasum) "
	else
		>&2 echo "fopus: sha1sum not found"
		exit 1
	fi
	declare -gr sha1sum_tool

	if command -v sha256sum &> /dev/null; then
		sha256sum_tool="$(command -v sha256sum)"
	elif command -v shasum &> /dev/null; then
		sha256sum_tool="$(command -v shasum) -a 256 "
	else
		>&2 echo "fopus: sha256sum not found"
		exit 1
	fi
	declare -gr sha256sum_tool

	return 0
}

show_help()
{
	cat << EOT
Usage:
    fopus [-1sgn] [-b SIZE] [-o OUTPUT] [-k SECKEY] FILE...

Options:
    -1         Put FILEs in one backup.
    -s         Don't split backup in parts.
    -b SIZE    Split backup pieces of SIZE. Default is 1G.
    -g         Group backups by file/date instead of date/name.
    -o OUTPUT  Backup in the directory at path OUTPUT.
    -k SECKEY  Minisign with SECKEY.
    -n         Don't perform any action.

Examples:
    $ fopus -o ~/Backups -b 1G Documents/ lorem-ipsum.txt
    $ fopus -1s Pictures/ Videos/
EOT
}

evaluate_files()
{
	declare -i i

	for i in "${!FILES[@]}"; do
		local file="${FILES[$i]}"

		if [[ ! -e "$file" ]]; then
			>&2 echo "fopus: $file: No such file or directory"
			exit 1
		elif [[ ! -r "$file" ]]; then
			>&2 echo "fopus: $file: Permission denied"
			exit 1
		fi

		FILES["$i"]=$(realpath "$file")
	done

	return 0
}

fopus_backup()
{
	local -r LIST_FILES=("$@")

	local BACKUP_FILE=""
	local BACKUP_PATH=""
	local BACKUP_DIR=""

	local -r ARCHIVE_UUID=$(uuidgen -r)

	local tmp=""

	REPO_NAME=$(basename -- "${LIST_FILES[0]}")
	REPO_NAME=$(echo -n "$REPO_NAME" | tr "[:space:]" "_" | tr -s "_")

	tmp=$(echo "${LIST_FILES[0]}" | "$sha1sum_tool")
	tmp="$REPO_NAME-${tmp:0:11}"

	if [[ "${CONFIG[groupbyname]}" = "true" ]]; then
		BACKUP_PATH="$OUTPUT_PATH/$tmp"
		BACKUP_DIR="backup_$DATE"
	else
		BACKUP_PATH="$OUTPUT_PATH/backup_$DATE"
		BACKUP_DIR="$tmp"
	fi

	local -r BACKUP_PATH="$BACKUP_PATH"
	local -r BACKUP_DIR="$BACKUP_DIR"

	CLEANUP_DIR="$BACKUP_PATH/$BACKUP_DIR"

	if [[ -e "$BACKUP_PATH/$BACKUP_DIR" ]]; then
		>&2 echo "fopus: cannot create backup: Backup exists"
		exit 1
	fi

	BACKUP_FILE="$BACKUP_PATH/$BACKUP_DIR/${REPO_NAME}.tar.xz"
	local -r BACKUP_FILE="$BACKUP_FILE"

	# show backup details
	echo -e "${JOB} ${LIST_FILES[0]}"
	if [[ "${CONFIG[one]}" = "true" ]]; then
		declare -i i=1
		N="${#LIST_FILES[@]}"
		while [[ $i -lt $N ]]; do
			echo "       ${LIST_FILES[$i]}"
			((i += 1))
		done
	fi

	if [[ "$DRY_RUN" = "false" ]]; then
		mkdir -p "$BACKUP_PATH/$BACKUP_DIR" || exit 1
	fi

	# compress
	if [[ "$DRY_RUN" = "false" ]]; then
		tar -cvpf - -- "${LIST_FILES[@]}" 2> "$BACKUP_PATH/$BACKUP_DIR/${REPO_NAME}.txt" |\
			xz --verbose --compress --threads=0 - > "$BACKUP_FILE"
	fi

	# encrypt
	if ! encrypt_file; then
		return 1
	fi

	# split
	if ! split_file; then
		return 1
	fi

	# sign
	if ! sign_files; then
		return 1
	fi

	# hash and file permission
	if ! hash_permission; then
		return 1
	fi

	# label
	if ! label_archive; then
		return 1
	fi

	return 0
}

encrypt_file()
{
	if [[ "$DRY_RUN" = "false" ]]; then
		local params=()
		if [[ -n "${CONFIG[ageRECIPIENT]}" ]]; then
			params+=(--recipient "${CONFIG[ageRECIPIENT]}")
		elif [[ -n "${CONFIG[agePATH]}" ]]; then
			params+=(--recipients-file "${CONFIG[agePATH]}")
		else
			params+=(--encrypt --passphrase)
		fi

		if ! "$age_tool" "${params[@]}" "$BACKUP_FILE" > "${BACKUP_FILE}.age"; then
			return 1
		fi
	fi

	return 0
}

split_file()
{
	if [[ "${CONFIG[partsize]}" = "-1" ]]; then
		return 0
	fi

	local FILE_SIZE=""
	local LIMIT_SIZE=""

	if [[ "$DRY_RUN" = "false" ]]; then
		FILE_SIZE=$(stat -c %s "$BACKUP_FILE.age")
		LIMIT_SIZE=$(echo "${CONFIG[partsize]}" | numfmt --from=iec)

		if [[ "$FILE_SIZE" -gt "$LIMIT_SIZE" ]]; then
			# split
			if ! split --verbose --bytes="${CONFIG[partsize]}" \
				"$BACKUP_FILE.age" "$BACKUP_FILE.age_"; then
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
		(
		cd "$BACKUP_PATH/$BACKUP_DIR" || exit 1
		if ! "$sha256sum_tool" "./"* > "./SHA256SUMS.txt"; then
			return 1
		fi
		)

		#sign
		local params=()
		if [[ -n "${CONFIG[trusted]}" ]]; then
			params+=(-t "${CONFIG[trusted]}")
		fi
		if [[ -n "${CONFIG[seckey]}" ]]; then
			params+=(-s "${CONFIG[seckey]}")
		fi

		if ! "$minisign_tool" "${params[@]}" -Sm "$BACKUP_PATH/$BACKUP_DIR/SHA256SUMS.txt"; then
			return 1
		fi
	fi

	return 0
}

hash_permission()
{
	# hashes
	if [[ "$DRY_RUN" = "false" ]]; then
		(
		cd "$BACKUP_PATH" || exit 1
		find "$BACKUP_DIR/" -type f -exec "$sha1sum_tool" {} \; >> "./SHA1SUMS.txt"
		)
		chmod 600 "$BACKUP_PATH/SHA1SUMS.txt"
	fi

	# file permission
	if [[ "$DRY_RUN" = "false" ]]; then
		if ! chmod 700 "$BACKUP_PATH/$BACKUP_DIR/"; then
			return 1
		fi
		(find "$BACKUP_PATH/$BACKUP_DIR/" -type f -exec chmod 600 {} \;)
		(find "$BACKUP_PATH/$BACKUP_DIR/" -type d -exec chmod 700 {} \;)
	fi

	return 0
}

label_archive()
{
	if [[ "$DRY_RUN" == "false" ]] &&\
	   [[ "$IS_LABELED" == "true" ]]; then
		cat << EOL > "$BACKUP_PATH/$BACKUP_DIR/label.txt"
# $ARCHIVE_UUID
# $(date -u --iso-8601=seconds)
#
$(printf "# %s\n" "${LIST_FILES[@]}")
EOL
	fi

	return 0
}

digest_options()
{
	local s_opt="false"
	local b_opt="false"
	local r_opt="false"
	local R_opt="false"

	while getopts "hvng1sb:o:k:t:r:R:l" opt; do
		case "$opt" in
			n) DRY_RUN="true" ;;

			l) IS_LABELED="true" ;;

			g) CONFIG[groupbyname]="true" ;;

			1) CONFIG[one]="true" ;;

			t) CONFIG[trusted]="$OPTARG" ;;

			s)
				if [[ "$b_opt" = "true" ]]; then
					>&2 echo "fopus: -b can't be used with -s"
					exit 2
				fi
				CONFIG[partsize]="-1"; s_opt="true" ;;

			b)
				if [[ "$s_opt" = "true" ]]; then
					>&2 echo "fopus: -s can't be used with -b"
					exit 2
				fi
				if ! split --bytes="$OPTARG" /dev/null; then
					exit 1
				fi
				CONFIG[partsize]="$OPTARG"; b_opt="true" ;;

			o)
				if [[ ! -d "$OPTARG" ]]; then
					>&2 echo "fopus: $OPTARG: No such directory"
					exit 1
				fi
				CONFIG[repopath]="$OPTARG" ;;

			k)
				if [[ ! -f "$OPTARG" ]]; then
					>&2 echo "fopus: $OPTARG: No such file"
					exit 1
				fi
				CONFIG[seckey]=$(realpath "$OPTARG") ;;

			r)
				if [[ "$R_opt" = "true" ]]; then
					>&2 echo "fopus: duplicate specification of age recipient"
					exit 1
				fi
				if ! "$age_tool" --recipient "$OPTARG" "$0" > /dev/null ; then
					exit 2
				fi
				CONFIG[ageRECIPIENT]="$OPTARG"; r_opt="true" ;;

			R)
				if [[ "$r_opt" = "true" ]]; then
					>&2 echo "fopus: duplicate specification of age recipient"
					exit 1
				fi
				if ! "$age_tool" --recipients-file "$OPTARG" "$0" > /dev/null ; then
					exit 2
				fi
				CONFIG[agePATH]=$(realpath "$OPTARG"); R_opt="true" ;;

			v) echo "v${VERSION}"
				exit 0 ;;

			h) show_help
				exit 0 ;;

			?) show_help
				exit 2 ;;
		esac
	done

	shift $((OPTIND - 1))
	FILES+=("$@")

	return 0
}


main()
{
	declare -A CONFIG=(
		[partsize]="1073741824"
		[repopath]="$(pwd -P)"
		[groupbyname]="false"
		[one]="false"
		[seckey]=""
		[trusted]=""
		[ageRECIPIENT]=""
		[agePATH]=""
	)

	local FILES=()
	DRY_RUN="false"
	IS_LABELED="false"

	if ! check_requirements; then
		exit 1
	fi

	if ! digest_options "$@"; then
		exit 1
	fi

	declare -gr CONFIG
	declare -gr DRY_RUN
	declare -gr IS_LABELED

	if ! evaluate_files; then
		exit 1
	fi
	local -r FILES

	if [[ -z "${FILES-}" ]]; then
		>&2 echo "fopus: missing file operand"
		echo "Try 'fopus --help' for more information."
		exit 1
	fi

	OUTPUT_PATH="${CONFIG[repopath]}"

	if [[ ! -d "$OUTPUT_PATH" ]]; then
		>&2 echo "fopus: $OUTPUT_PATH: No such directory"
		exit 1
	elif [[ "$OUTPUT_PATH" =~ ^"$HOME"$ ]]; then
		>&2 echo "fopus: $OUTPUT_PATH: Permission denied"
		exit 1
	elif [[ ! -w "$OUTPUT_PATH" ]]; then
		>&2 echo "fopus: $OUTPUT_PATH: Permission denied"
		exit 1
	fi

	OUTPUT_PATH=$(realpath "$OUTPUT_PATH")
	OUTPUT_PATH=${OUTPUT_PATH%/}
	declare -r OUTPUT_PATH="$OUTPUT_PATH"

	trap cleanup SIGINT SIGTERM
	echo "Repository $OUTPUT_PATH"

	declare JOB=""
	if [[ "${CONFIG[one]}" = "true" ]]; then
		JOB="Backup"
		fopus_backup "${FILES[@]}"
	else
		declare -i i=0
		declare -ir N="${#FILES[@]}"
		local file=""
		for file in "${FILES[@]}"; do
			((i += 1))
			JOB="Backup $i of $N"
			if ! fopus_backup "$file"; then
				return 1
			fi
		done
	fi

	exit 0
}


main "$@"

exit 0