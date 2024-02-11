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

declare -r VERSION="3.0.0-rc1"

DATE=$(date +%Y-%m-%d)
declare -r DATE

DRY_RUN="false"

declare -A CONFIG=(
	[partsize]="1073741824"
	[repopath]="$(pwd -P)"
	[groupbyname]="false"
	[one]="false"
	[seckey]=""
)

check_requirements()
{
	declare -ar apps=(age minisign tar xz shasum)
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
	echo "Usage:"
	echo -e "\tfopus [--one] [--no-split | --split-size SIZE] [--group-by-name] [--ouput OUTPUT] FILE..."
	echo ""
	echo "Options:"
	echo -e "\t-1, --one\t\tPut FILEs in one backup."
	echo -e "\t-s, --no-split\t\tDon't split backup in parts."
	echo -e "\t-b, --split-size SIZE\tSplit backup pieces of SIZE. Default is 1G."
	echo -e "\t-g, --group-by-name\tGroup backups by file/date instead of date/name."
	echo -e "\t-o, --output OUTPUT\tBackup in the directory at path OUTPUT."
	echo -e "\t-k, --seckey SECKEY_FILE\tMinisign with SECKEY_FILE."
	echo -e "\t-n, --dry-run\t\tDon't perform any action."
	echo ""
	echo "Examples:"
	echo -e "\t$ fopus --output ~/Backups --split-size 1G Documents/ lorem-ipsum.txt"
	echo -e "\t$ fopus --one --no-split Pictures/ Videos/"
}

main()
{
	check_requirements

	declare -a FILES=("$@")

	if [[ -z "$FILES" ]]; then
		>&2 echo "fopus: missing file operand"
		echo "Try 'fopus --help' for more information."
		exit 1
	fi

	declare -r DRY_RUN="$DRY_RUN"

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

	evaluate_files

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
			((i++))
			JOB="Backup $i of $N"
			if ! fopus_backup "$file"; then
				return 1
			fi
		done
	fi

	exit 0
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

		FILES["$i"]=$(realpath "$file")
		((i++))
	done

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
			((i++))
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
	if [[ "$DRY_RUN" = "false" ]]; then
		if ! age --encrypt --passphrase "$BACKUP_FILE" > "${BACKUP_FILE}.age"; then
			return 1
		fi
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
		if [[ -z "${CONFIG[seckey]}" ]]; then
			if ! minisign -Sm "$BACKUP_PATH/$BACKUP_DIR/SHA256SUMS.txt"; then
				return 1
			fi
		else
			if ! minisign -Sm "$BACKUP_PATH/$BACKUP_DIR/SHA256SUMS.txt" -s "${CONFIG[seckey]}"; then
				return 1
			fi
		fi
	fi

	return 0
}

hash_permission()
{
	echo "$BACKUP_PATH/$BACKUP_DIR/"
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

if [[ -z "$1" ]]; then
	>&2 echo "fopus: missing file operand"
	echo "Try 'fopus --help' for more information."
	exit 1
fi

s_opt="false"
b_opt="false"
while getopts "hvng1sb:o:k:" opt; do
    case "$opt" in
		n) DRY_RUN="true" ;;

		g) CONFIG[groupbyname]="true" ;;

		1) CONFIG[one]="true" ;;

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

		v) echo "v${VERSION}"
			exit 0 ;;

		h) show_help
			exit 0 ;;

        ?) show_help
			exit 2 ;;
    esac
done

shift $((OPTIND - 1))
main "$*"

exit 0