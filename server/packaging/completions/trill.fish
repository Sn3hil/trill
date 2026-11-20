# fish completion for trill

function __fish_trill_needs_command
    set -l cmd (commandline -opc)
    if test (count $cmd) -eq 1
        return 0
    end
    return 1
end

function __fish_trill_using_command
    set -l cmd (commandline -opc)
    if test (count $cmd) -gt 1
        if test $argv[1] = $cmd[2]
            return 0
        end
    end
    return 1
end

complete -c trill -n '__fish_trill_needs_command' -s h -l help -d 'Show help'
complete -c trill -n '__fish_trill_needs_command' -s v -l version -d 'Show version'
complete -c trill -n '__fish_trill_needs_command' -l json -d 'Print machine-readable JSON'
complete -c trill -n '__fish_trill_needs_command' -l socket -d 'Override IPC socket path' -r

complete -c trill -n '__fish_trill_needs_command' -a pair -d 'Open pairing window'
complete -c trill -n '__fish_trill_needs_command' -a list -d 'List paired phones'
complete -c trill -n '__fish_trill_needs_command' -a status -d 'Show daemon status'
complete -c trill -n '__fish_trill_needs_command' -a start -d 'Ask phone to start streaming'
complete -c trill -n '__fish_trill_needs_command' -a stop -d 'Stop streaming'
complete -c trill -n '__fish_trill_needs_command' -a unpair -d 'Remove phone pin'
complete -c trill -n '__fish_trill_needs_command' -a rename -d 'Rename phone'
complete -c trill -n '__fish_trill_needs_command' -a shutdown -d 'Stop daemon'

complete -c trill -n '__fish_trill_using_command pair' -l timeout -d 'Window duration in seconds' -r
