cnc_daemon_cmd() {
    echo $@ > $cnc_cmd_input
    cat $cnc_cmd_output
}

cnc_read_into_file() {
  dest_file=$2

  read -r encoded && echo -n $encoded | base64 -d -w0 | gzip -d > $dest_file
}
#Important, keep the trailing newline. Otherwise the stdin isn't submitted to bash.
