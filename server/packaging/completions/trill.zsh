#compdef trill

_trill() {
    local -a commands
    commands=(
        'pair:Open a pairing window and show the code'
        'list:List paired phones'
        'status:Show daemon, sink, sessions and stream status'
        'start:Ask a connected phone to start streaming'
        'stop:Stop one stream, or all when no device is given'
        'unpair:Remove the pin and drop the session'
        'rename:Change a phone label'
        'shutdown:Stop the daemon'
    )

    _arguments -C \
        '--json[Print machine-readable JSON]' \
        '--socket[Override the daemon IPC socket path]:socket:_files' \
        '(-h --help)'{-h,--help}'[Show help]' \
        '(-v --version)'{-v,--version}'[Show version]' \
        '1: :->command' \
        '*:: :->args'

    case $state in
        command)
            _describe -t commands 'trill commands' commands
            ;;
        args)
            case $line[1] in
                pair)
                    _arguments '--timeout[Window duration in seconds]:seconds:'
                    ;;
                start|unpair)
                    _arguments '1:device:'
                    ;;
                stop)
                    _arguments '::device:'
                    ;;
                rename)
                    _arguments '1:device:' '2:name:'
                    ;;
            esac
            ;;
    esac
}

_trill "$@"
