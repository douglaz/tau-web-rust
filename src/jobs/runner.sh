umask 077
d=$1
# Linux stat field 22 distinguishes this process from a recycled PID on the same boot.
identity() {
    IFS= read -r process < "/proc/$1/stat" || return 1
    process=${process##*) }
    set -- $process
    shift 19
    printf '%s\n' "$1"
}
start=$(identity "$$") || exit 1
printf '%s %s\n' "$$" "$start" > "$d/runner.pending" || exit 1
mv "$d/runner.pending" "$d/runner" || exit 1
# exec preserves the command's own PID and start time, without sharing wrapper variables.
sh -c '
    d=$1
    IFS= read -r process < "/proc/$$/stat" || exit 1
    process=${process##*) }
    set -- $process
    shift 19
    printf "%s %s\n" "$$" "$1" > "$d/pid.pending" || exit 1
    mv "$d/pid.pending" "$d/pid" || exit 1
    exec sh "$d/command"
' sh "$d" > "$d/stdout" 2> "$d/stderr" &
command_pid=$!
while [ ! -f "$d/pid" ]; do
    kill -0 "$command_pid" 2>/dev/null || { [ -f "$d/pid" ] && break; exit 1; }
    # GNU coreutils (Arch) and busybox (Alpine) accept fractional sleep.
    sleep 0.05
done
: > "$d/ready"
wait "$command_pid"
status=$?
# POSIX wait cannot distinguish signal death from a normal exit above 128.
if [ "$status" -le 128 ]; then
    printf '%s\n' "$status" > "$d/exit.pending" || exit 1
    mv "$d/exit.pending" "$d/exit" || exit 1
fi
