# bash completion for trill

_trill() {
    local cur prev words cword
    _init_completion || return

    local commands="pair list status start stop unpair rename shutdown"
    local flags="--json --socket --help -h --version -v"

    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$commands $flags" -- "$cur") )
        return 0
    fi

    local cmd="${words[1]}"
    case "$cmd" in
        pair)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--timeout --json --help" -- "$cur") )
            fi
            ;;
        list|status|shutdown)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--json --help" -- "$cur") )
            fi
            ;;
        start|stop|unpair)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--json --help" -- "$cur") )
            fi
            ;;
        rename)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--json --help" -- "$cur") )
            fi
            ;;
        *)
            ;;
    esac
}

complete -F _trill trill
