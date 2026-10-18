alive() {
    case $1 in ''|*[!0-9]*) return 1;; esac
    case $2 in ''|*[!0-9]*) return 1;; esac
    [ -r "/proc/$1/stat" ] || return 1
    IFS= read -r process < "/proc/$1/stat" || return 1
    process=${process##*) }
    case $process in Z*|X*) return 1;; esac
    expected_start=$2
    set -- $process
    shift 19
    [ "$1" = "$expected_start" ]
}
pause() {
    passes=$((passes + 1))
    # GNU coreutils (Arch) and busybox (Alpine) accept fractional sleep.
    if [ "$passes" -le 20 ]; then sleep 0.05
    elif [ "$passes" -le 28 ]; then sleep 0.25
    else sleep 1
    fi
}
fail() {
    printf 'cannot read complete job record file: %s\n' "$1" >&2
    exit 1
}
bytes() {
    [ -f "$1" ] && [ -r "$1" ] || fail "$1"
    encoded=$(od -An -v -tx1 "$1") || fail "$1"
    printf '%s' "$encoded" | tr -d ' \n'
}
# Count exact bytes before read, which silently discards NULs in some shells.
# Accepted scalars are ASCII, so the value length plus its delimiter must match.
# Immutable files are checked once before waiting; exit is checked when found.
line() {
    [ -f "$1" ] && [ -r "$1" ] || fail "$1"
    size=$(wc -c < "$1") || fail "$1"
    value=
    delimiter=0
    {
        if IFS= read -r value; then delimiter=1
        else [ -n "$value" ] || fail "$1"
        fi
        extra=
        if IFS= read -r extra || [ -n "$extra" ]; then fail "$1"; fi
    } < "$1" || fail "$1"
    [ "$size" -eq "$((${#value} + delimiter))" ] || fail "$1"
}
boot_id() {
    line "$1"
    case $value in ''|*[!a-zA-Z0-9-]*) fail "$1";; esac
}
process_id() {
    identity_file=$1
    line "$1"
    case $value in *[!0-9\ ]*) fail "$1";; esac
    set -- $value
    [ "$#" -eq 2 ] || fail "$identity_file"
    ident_pid=$1; ident_start=$2
    [ "$value" = "$ident_pid $ident_start" ] || fail "$identity_file"
    case $ident_pid in 0) ;; 0*) fail "$identity_file";; esac
    [ "${#ident_pid}" -le 10 ] && [ "$ident_pid" -le 4294967295 ] || fail "$identity_file"
}
exit_code() {
    line "$1"
    case $value in ''|*[!0-9]*) fail "$1";; esac
    [ "${#value}" -le 3 ] && [ "$value" -le 128 ] || fail "$1"
    case $value in 0) ;; 0*) fail "$1";; esac
    status=$value
}
if [ ! -d "$d" ]; then
    printf '{"kind":"missing"}\n'
    exit 0
fi
# A killed launch can leave a reserved directory without a complete record. It proves
# neither that the command started nor that it ended. Preserve any received command bytes.
if [ ! -f "$d/ready" ]; then
    machine=null
    command=null
    if [ -e "$d/machine" ] || [ -L "$d/machine" ]; then machine=\"$(bytes "$d/machine")\" || exit 1; fi
    if [ -e "$d/command" ] || [ -L "$d/command" ]; then command=\"$(bytes "$d/command")\" || exit 1; fi
    printf '{"kind":"incomplete","machine":%s,"command":%s}\n' "$machine" "$command"
    exit 0
fi
boot_id /proc/sys/kernel/random/boot_id
boot=$value
boot_id "$d/boot"
recorded_boot=$value
process_id "$d/pid"
pid=$ident_pid; command_start=$ident_start
process_id "$d/runner"
runner=$ident_pid; runner_start=$ident_start
passes=0
while :; do
    living=false
    status=null
    # An exit record is final, even if a recorded PID now belongs to another process.
    if [ -e "$d/exit" ] || [ -L "$d/exit" ]; then
        exit_code "$d/exit"
    else
        if [ "$boot" = "$recorded_boot" ]; then
            if alive "$pid" "$command_start"; then living=true; fi
            if [ "$wait_job" = true ] && { [ "$living" = true ] || alive "$runner" "$runner_start"; }; then
                # The runner may still be publishing a normal exit after the command ended.
                pause
                continue
            fi
        fi
        # Publication may have completed between the first check and observing runner death.
        if [ -e "$d/exit" ] || [ -L "$d/exit" ]; then exit_code "$d/exit"; fi
    fi
    machine=$(bytes "$d/machine") || exit 1
    command=$(bytes "$d/command") || exit 1
    stdout=$(bytes "$d/stdout") || exit 1
    stderr=$(bytes "$d/stderr") || exit 1
    printf '{"kind":"present","machine":"%s","command":"%s","boot":"%s","current_boot":"%s","pid":%s,"alive":%s,"exit_status":%s,"stdout":"%s","stderr":"%s"}\n' \
        "$machine" "$command" "$recorded_boot" "$boot" \
        "$pid" "$living" "$status" "$stdout" "$stderr"
    break
done
