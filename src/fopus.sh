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
	>&2 echo "fopus: permission denied"
	exit 1
fi

declare -r VERSION="4.0.0-rc1"

printf -v DATE "%(%Y-%m-%d)T" -1
declare -r DATE

declare -g CLEANUP_DIR=""

cleanup()
{
	declare -ri RC="$?"
	trap - SIGINT SIGTERM EXIT

	declare -rg CLEANUP_DIR

	if [[ "$RC" -eq 0 ]]; then
		:
	elif [[ ! -e "$CLEANUP_DIR" ]]; then
		:
	else
		local -r target=$(realpath -e "$CLEANUP_DIR")

		if [[ ! -O "$target" ]]; then
			:
		elif [[ ! -d "$target" ]]; then
			:
		elif [[ -z "${target%/*}" ]]; then
			:
		elif [[ "$target" == "/" ]]; then
			:
		else
			rm -r "$target"
		fi
	fi

	kill -SIGINT $$
}

check_requirements()
{
	local -r apps=(tar xz realpath tr split numfmt stat basename find cat uuidgen date)

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

	if command -v b3sum &> /dev/null; then
		checksum_tool="$(command -v b3sum)"
	elif command -v b2sum &> /dev/null; then
		checksum_tool="$(command -v b2sum)"
	elif command -v sha256sum &> /dev/null; then
		checksum_tool="$(command -v sha256sum)"
	elif command -v shasum &> /dev/null; then
		checksum_tool="$(command -v shasum) -a 256 "
	else
		>&2 echo "fopus: hash functions not found"
		exit 1
	fi
	declare -gr checksum_tool

	return 0
}

show_help()
{
	cat << EOT
Usage:
    fopus [-1gnql] [-s | -b SIZE] [-o OUTPUT] [-k SECKEY] [-t COMMENT] \\
		[-r RECIPIENT | -R PATH] FILE...

Options:
    -1            Put FILEs in one backup.
    -g            Group backups by file/date instead of date/name.
    -o OUTPUT     Backup in the directory at path OUTPUT.
    -n            Don't perform any action.
    -q            Quieter mode.
    -l            Create a label for the backup.

Split options:
    -s            Don't split backup in parts.
    -b SIZE       Split backup pieces of SIZE. Default is 2G.

Minisign options:
    -k SECKEY     Minisign with SECKEY.
    -t COMMENT    Minisign add a one-line trusted COMMENT.

Age options:
    -r RECIPIENT  Age encrypt to the specified RECIPIENT.
    -R PATH       Age encrypt to recipients listed at PATH.

Examples:
    $ fopus -o ~/Backups -b 1G Documents/ lorem-ipsum.txt
    $ fopus -1s Pictures/ Videos/
    $ fopus -l -t "Trusted lorem ipsum" -R ~/.age/projects.pub Projects/
EOT
}

evaluate_files()
{
	local SELECT=()
	local file

	for file in "${FILES[@]}"; do
		if [[ ! -e "$file" ]]; then
			>&2 echo "fopus: $file: No such file or directory"
			exit 1
		elif [[ ! -r "$file" ]]; then
			>&2 echo "fopus: $file: Permission denied"
			exit 1
		fi

		file=$(realpath -e "$file")
		SELECT+=("$file")
	done

	FILES=()
	FILES=("${SELECT[@]}")

	return 0
}

fopus_backup()
{
	local -r LIST_FILES=("$@")

	local BACKUP_FILE=""
	local BACKUP_PATH=""
	local BACKUP_DIR=""

	local -r ARCHIVE_UUID=$(uuidgen -r)
	local ARCHIVE_SHA1SUM=""

	local tmp=""

	REPO_NAME=$(basename -- "${LIST_FILES[0]}")
	REPO_NAME=$(echo -n "$REPO_NAME" | tr "[:space:]" "_" | tr -s "_")
	REPO_NAME="${REPO_NAME#"${REPO_NAME%%[^.]*}"}"

	tmp=$(echo "${LIST_FILES[0]}" | "$sha1sum_tool")
	tmp="$REPO_NAME-${tmp:0:11}"

	if [[ "$IS_GROUP_INVERT" == "true" ]]; then
		BACKUP_PATH="$OUTPUT_PATH/$tmp"
		BACKUP_DIR="backup_$DATE"
	else
		BACKUP_PATH="$OUTPUT_PATH/backup_$DATE"
		BACKUP_DIR="$tmp"
	fi

	local -r BACKUP_PATH="$BACKUP_PATH"
	local -r BACKUP_DIR="$BACKUP_DIR"

	CLEANUP_DIR="$BACKUP_PATH/$BACKUP_DIR"

	BACKUP_FILE="$BACKUP_PATH/$BACKUP_DIR/${REPO_NAME}.tar.xz"
	local -r BACKUP_FILE="$BACKUP_FILE"

	# show backup details
	if [[ "$IS_QUIET" == "false" ]]; then
		echo -e "${JOB} ${LIST_FILES[0]}"
		if [[ "$IS_SINGLETON" == "true" ]]; then
			declare -i i=1
			N="${#LIST_FILES[@]}"
			while [[ $i -lt $N ]]; do
				echo "       ${LIST_FILES[$i]}"
				((i += 1))
			done
		fi
	fi

	if [[ -e "$BACKUP_PATH/$BACKUP_DIR" ]]; then
		>&2 echo "fopus: cannot create backup: directory is not empty"
		return 0
	fi

	if [[ "$DRY_RUN" == "false" ]]; then
		mkdir -p "$BACKUP_PATH/$BACKUP_DIR" || exit 1
	fi

	# compress
	if [[ "$DRY_RUN" == "false" ]]; then
		local params=()
		[[ "$IS_QUIET" == "false" ]] && params+=(--verbose)
		[[ "$IS_XZ_PRESET_NINE" == "true" ]] && params+=(-9)
		tar -cvpf - -- "${LIST_FILES[@]}" 2> "$BACKUP_PATH/$BACKUP_DIR/${REPO_NAME}.list.txt" |\
			xz "${params[@]}" --compress --threads=0 - > "$BACKUP_FILE"
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

	# hash files
	if ! hash_files; then
		return 1
	fi

	# file permission
	if ! file_permission; then
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
	if [[ "$DRY_RUN" == "false" ]]; then
		local params=()
		if [[ -n "$AGE_RECIPIENT_STRING" ]]; then
			params+=(--recipient "$AGE_RECIPIENT_STRING")
		elif [[ -n "$AGE_RECIPIENT_PATH" ]]; then
			params+=(--recipients-file "$AGE_RECIPIENT_PATH")
		else
			[[ "$IS_QUIET" == "true" ]] && echo "${REPO_NAME}.tar.xz"
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
	if [[ "$SPLIT_BYTES" -le 0 ]]; then
		return 0
	fi

	local FILE_SIZE=""
	local LIMIT_SIZE=""

	if [[ "$DRY_RUN" == "false" ]]; then
		FILE_SIZE=$(stat -c %s "$BACKUP_FILE.age")
		LIMIT_SIZE=$(echo "$SPLIT_BYTES" | numfmt --from=iec)

		if [[ "$FILE_SIZE" -gt "$LIMIT_SIZE" ]]; then
			local params=()
			[[ "$IS_QUIET" == "false" ]] && params+=(--verbose)
			if ! split "${params[@]}" --bytes="$SPLIT_BYTES" \
				"$BACKUP_FILE.age" "$BACKUP_FILE.age_"; then
					return 1
			fi
		fi
	fi

	return 0
}

sign_files()
{
	if [[ "$DRY_RUN" == "false" ]]; then
		# hash
		(
		cd "$BACKUP_PATH/$BACKUP_DIR" || exit 1
		if ! "$checksum_tool" "./"* > "./CHECKSUMS.txt"; then
			return 1
		fi
		)

		#sign
		local params=()
		if [[ -n "$MINISIGN_TRUSTED_COMMENT" ]]; then
			params+=(-t "$MINISIGN_TRUSTED_COMMENT")
		fi
		if [[ -n "$MINISIGN_KEY_PATH" ]]; then
			params+=(-s "$MINISIGN_KEY_PATH")
		fi

		if ! "$minisign_tool" "${params[@]}" -Sm "$BACKUP_PATH/$BACKUP_DIR/CHECKSUMS.txt"; then
			return 1
		fi
	fi

	return 0
}

hash_files()
{
	if [[ "$DRY_RUN" == "false" ]]; then
		if [[ "$IS_LABELED" == "false" ]]; then
			if ! (
				cd "$BACKUP_PATH" || exit 1
				if ! "$sha1sum_tool" "./$BACKUP_DIR/"* > "./SHA1SUMS.txt"; then
					return 1
				fi
			); then
				return 1
			fi
			chmod 600 "$BACKUP_PATH/SHA1SUMS.txt"
		else
			ARCHIVE_SHA1SUM=$(
			cd "$BACKUP_PATH/$BACKUP_DIR" || return 1
			"$sha1sum_tool" "./"*
			)
		fi
	fi

	return 0
}

file_permission()
{
	if [[ "$DRY_RUN" == "false" ]]; then
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
$ARCHIVE_SHA1SUM
EOL
		chmod 400 "$BACKUP_PATH/$BACKUP_DIR/label.txt"
	fi

	return 0
}

digest_options()
{
	local r_opt="false"
	local R_opt="false"

	while getopts "hvng1b:o:s:t:r:R:ql9" opt; do
		case "$opt" in
			n) DRY_RUN="true" ;;

			q) IS_QUIET="true" ;;

			l) IS_LABELED="true" ;;

			9) IS_XZ_PRESET_NINE="true" ;;

			g) IS_GROUP_INVERT="true" ;;

			1) IS_SINGLETON="true" ;;

			t) MINISIGN_TRUSTED_COMMENT="$OPTARG" ;;

			b)
				SPLIT_BYTES="$OPTARG"
				if [[ "$SPLIT_BYTES" =~ ^[-+]?[0-9]+$ ]] &&\
				   [[ "$SPLIT_BYTES" -le 0 ]]; then
					SPLIT_BYTES=0
				elif ! split --bytes="$SPLIT_BYTES" /dev/null; then
					exit 1
				fi
				;;

			o)
				if [[ ! -d "$OPTARG" ]]; then
					>&2 echo "fopus: $OPTARG: No such directory"
					exit 1
				fi
				REPOSITORY_PATH="$OPTARG" ;;

			s)
				if [[ ! -f "$OPTARG" ]]; then
					>&2 echo "fopus: $OPTARG: No such file"
					exit 1
				fi
				MINISIGN_KEY_PATH=$(realpath -e "$OPTARG") ;;

			r)
				if [[ "$R_opt" == "true" ]]; then
					>&2 echo "fopus: duplicate specification of age recipient"
					exit 1
				fi
				if ! "$age_tool" --recipient "$OPTARG" "$0" > /dev/null ; then
					exit 2
				fi
				AGE_RECIPIENT_STRING="$OPTARG"; r_opt="true" ;;

			R)
				if [[ "$r_opt" == "true" ]]; then
					>&2 echo "fopus: duplicate specification of age recipient"
					exit 1
				fi
				if ! "$age_tool" --recipients-file "$OPTARG" "$0" > /dev/null ; then
					exit 2
				fi
				AGE_RECIPIENT_PATH=$(realpath -e "$OPTARG"); R_opt="true" ;;

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
	local FILES=()

	REPOSITORY_PATH="$(pwd -P)"
	IS_GROUP_INVERT="false"
	IS_SINGLETON="false"
	DRY_RUN="false"
	IS_QUIET="false"
	IS_LABELED="false"
	IS_XZ_PRESET_NINE="false"
	SPLIT_BYTES=2147483648
	AGE_RECIPIENT_STRING=""
	AGE_RECIPIENT_PATH=""
	MINISIGN_TRUSTED_COMMENT=""
	MINISIGN_KEY_PATH=""

	if ! check_requirements; then
		exit 1
	fi

	if ! digest_options "$@"; then
		exit 1
	fi

	declare -gr REPOSITORY_PATH
	declare -gr IS_GROUP_INVERT
	declare -gr IS_SINGLETON
	declare -gr DRY_RUN
	declare -gr IS_QUIET
	declare -gr IS_LABELED
	declare -gr IS_XZ_PRESET_NINE
	declare -gr SPLIT_BYTES
	declare -gr AGE_RECIPIENT_STRING
	declare -gr AGE_RECIPIENT_PATH
	declare -gr MINISIGN_TRUSTED_COMMENT
	declare -gr MINISIGN_KEY_PATH

	if ! evaluate_files; then
		exit 1
	fi
	local -r FILES

	if [[ -z "${FILES-}" ]]; then
		>&2 echo "fopus: missing file operand"
		echo "Try 'fopus -h' for more information."
		exit 1
	fi

	OUTPUT_PATH="$REPOSITORY_PATH"

	if [[ ! -d "$OUTPUT_PATH" ]]; then
		>&2 echo "fopus: $OUTPUT_PATH: No such directory"
		exit 1
	elif [[ ! -w "$OUTPUT_PATH" ]]; then
		>&2 echo "fopus: $OUTPUT_PATH: Permission denied"
		exit 1
	fi

	OUTPUT_PATH=$(realpath -e "$OUTPUT_PATH")
	declare -r OUTPUT_PATH="$OUTPUT_PATH"

	if [[ -z "${OUTPUT_PATH%/*}" ]]; then
		>&2 echo "fopus: $OUTPUT_PATH: Permission denied"
		exit 1
	fi

	for file in "${FILES[@]}"; do
		if [[ "$OUTPUT_PATH" == "$file/"* ]]; then
			>&2 echo "fopus: invalid output path"
			exit 1
		fi
	done

	trap cleanup SIGINT SIGTERM EXIT
	[[ "$IS_QUIET" == "false" ]] && echo "Repository $OUTPUT_PATH"

	declare JOB=""
	if [[ "$IS_SINGLETON" == "true" ]]; then
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
	trap - EXIT

	exit 0
}


main "$@"

exit 0
