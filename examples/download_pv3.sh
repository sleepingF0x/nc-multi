#!/usr/bin/env bash
# Download with Bash builtins; chmod is the only external command.
# Set PV_HOST and PV_KEY in a private copy before submitting it with batch.
(
    export LC_ALL=C
    umask 077
    host=${PV_HOST:-}
    port=${PV_PORT:-80}
    resource=${PV_PATH:-/d/pv3}
    key=${PV_KEY:-}
    output=${PV_OUTPUT:-pv3}
    deadline=${PV_TIMEOUT:-300}
    worker=

    fail() { printf '[error] %s\n' "$*" >&2; return 1; }

    [[ $host && $host != *[!a-zA-Z0-9.-]* ]] || { fail 'Set PV_HOST to a valid download hostname or IPv4 address.'; exit 1; }
    [[ $port && $port != *[!0-9]* && ${#port} -le 5 ]] || { fail 'Invalid port.'; exit 1; }
    port=$((10#$port))
    ((port >= 1 && port <= 65535)) || { fail 'Invalid port.'; exit 1; }
    [[ $resource == /* && $resource != *[[:space:][:cntrl:]]* ]] || { fail 'Invalid request path.'; exit 1; }
    [[ $key && $key != *[!a-zA-Z0-9]* ]] || { fail 'Set PV_KEY to the download key (letters and digits only).'; exit 1; }
    [[ $deadline && $deadline != *[!0-9]* && ${#deadline} -le 5 ]] || { fail 'PV_TIMEOUT must be whole seconds, 1..86400.'; exit 1; }
    deadline=$((10#$deadline))
    ((deadline >= 1 && deadline <= 86400)) || { fail 'PV_TIMEOUT must be whole seconds, 1..86400.'; exit 1; }
    [[ $output == /* ]] || output=./$output
    [[ ! -e $output && ! -L $output ]] || { fail "Refusing to overwrite: $output"; exit 1; }
    command -v chmod >/dev/null || { fail 'chmod is required to add execute permission.'; exit 1; }

    read_header() {
        IFS= read -r -n 8192 line <&3 || { fail 'Incomplete HTTP headers.'; return 1; }
        [[ $line == *$'\r' && ${#line} -lt 8192 ]] || { fail 'Malformed or oversized HTTP header line.'; return 1; }
        line=${line%$'\r'}
        [[ $line != *$'\r'* ]] || { fail 'Malformed HTTP header line.'; return 1; }
        header_bytes=$((header_bytes + ${#line} + 2))
        ((header_bytes <= 65536)) || { fail 'HTTP headers exceed 64 KiB.'; return 1; }
    }

    download() {
        local line version status reason field value length= header_bytes=0
        local chunk want count received=0
        printf '[connect] %s:%s\n' "$host" "$port" >&2
        exec 3<>/dev/tcp/"$host"/"$port" || { fail 'DNS resolution or TCP connection failed; see the error above.'; return 1; }
        printf 'GET %s HTTP/1.0\r\nHost: %s:%s\r\nX-PV: %s\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n' \
            "$resource" "$host" "$port" "$key" >&3 || { fail 'Could not send the HTTP request.'; return 1; }
        read_header || return 1
        IFS=' ' read -r version status reason <<< "$line"
        [[ $version == HTTP/1.0 || $version == HTTP/1.1 ]] || { fail 'Invalid HTTP status line.'; return 1; }
        [[ $status == 200 ]] || { fail "HTTP ${status:-unknown}; download refused."; return 1; }
        while :; do
            read_header || return 1
            [[ $line ]] || break
            [[ $line == *:* && $line != [[:blank:]]* ]] || { fail 'Malformed HTTP header.'; return 1; }
            field=${line%%:*}
            value=${line#*:}
            value=${value#"${value%%[![:blank:]]*}"}
            value=${value%"${value##*[![:blank:]]}"}
            case $field in
                [Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ll][Ee][Nn][Gg][Tt][Hh])
                    [[ ! $length && $value && $value != *[!0-9]* && ${#value} -le 18 ]] || { fail 'Invalid or duplicate Content-Length.'; return 1; }
                    length=$((10#$value))
                    ;;
                [Tt][Rr][Aa][Nn][Ss][Ff][Ee][Rr]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg])
                    fail 'Transfer-Encoding is unsupported; serve an unencoded response with Content-Length.'
                    return 1
                    ;;
                [Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[Ee][Nn][Cc][Oo][Dd][Ii][Nn][Gg])
                    [[ $value == [Ii][Dd][Ee][Nn][Tt][Ii][Tt][Yy] ]] || { fail 'Compressed response is unsupported.'; return 1; }
                    ;;
            esac
        done
        [[ $length ]] && ((length > 0)) || { fail 'A positive Content-Length is required to detect truncated files.'; return 1; }
        printf '[download] expecting %s bytes\n' "$length" >&2
        # noclobber protects existing files, including a concurrent downloader's output.
        set -C
        exec 4>"$output" || { fail "Cannot create output without overwriting: $output"; return 1; }
        while ((received < length)); do
            want=$((length - received))
            ((want <= 16384)) || want=16384
            chunk=
            if IFS= read -r -d '' -n "$want" chunk <&3; then
                count=${#chunk}
                printf '%s' "$chunk" >&4 || { fail 'Writing the output file failed.'; return 1; }
                # A successful short read consumed a NUL delimiter; restore that byte.
                if ((count < want)); then
                    printf '\0' >&4 || { fail 'Writing the output file failed.'; return 1; }
                    count=$((count + 1))
                fi
                received=$((received + count))
            else
                fail "Incomplete body: received $((received + ${#chunk})) of $length bytes."
                return 1
            fi
        done
        exec 3<&- 3>&- 4>&-
        printf '[download] received %s bytes\n' "$received" >&2
    }

    cleanup() {
        if [[ $worker ]]; then
            kill -KILL "$worker" 2>/dev/null || :
            wait "$worker" 2>/dev/null || :
        fi
    }
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    # A timed pipe read supervises the entire worker, including DNS and TCP connect.
    # No sleep, timeout, curl, wget, cat, mv, or rm process is needed.
    exec 5< <(if download; then printf '0\n'; else printf '1\n'; fi)
    worker=$!
    started=$SECONDS
    if IFS= read -r -t "$deadline" result <&5; then
        wait "$worker" 2>/dev/null || :  # Bash 3.2 may already have reaped a process substitution.
        worker=
        exec 5<&-
        [[ $result == 0 ]] || { fail 'Download failed; any partial output is not executable. Choose a new filename before retrying.'; exit 1; }
    else
        read_status=$?
        if ((read_status > 128 || SECONDS - started >= deadline)); then
            fail "Download deadline exceeded (${deadline}s); any partial output is not executable."
            exit 124
        fi
        fail 'Download worker ended without a result.'
        exit 1
    fi
    command chmod u+x "$output" || { fail 'Download completed, but chmod failed.'; exit 1; }
    printf '[ready] %s downloaded and executable; not started.\n' "$output"
)
