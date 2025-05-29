#!/bin/bash

width=60
height=12

cur_height=$(tput lines)
cur_width=$(tput cols)

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Just to make it as bullet-proof as possible we will search where it should be.

SHYLL_PATH="$SCRIPT_DIR/build/shyll"

if [ ! -f "$SHYLL_PATH" ]; then
    SHYLL_PATH="$SCRIPT_DIR/cmake-buil-debug/shyll"
fi

if [ ! -f "$SHYLL_PATH" ]; then
    SHYLL_PATH="$SCRIPT_DIR/cmake-buil-release/shyll"
fi

if [ ! -f "$SHYLL_PATH" ]; then
    SHYLL_PATH="$SCRIPT_DIR/shyll"
fi

validate_dependencies() {
  if [ $cur_height -lt $height ]; then
    echo "Terminal is too small. Pleas ensure the height is at least $MIN_HEIGHT"
    exit 1
  fi

  if [ $cur_width -lt $width ]; then
    echo "Terminal is too small. Pleas ensure the width is at least $MIN_WIDTH"
    exit 1
  fi

  if ! command -v whiptail > /dev/null; then
    echo "Dependency whiptail is not available. Please ensure the 'whiptail' command is available if this environment. If not, please install it."
    exit 1
  fi

  if ! command -v expect > /dev/null; then
    whiptail --msgbox "Error, the dependency 'expect' is not available. Please ensure the 'expect' command is available in this environment:\n   'apt install expect'\n\n Terminating..." $height $width --title "Error"
    exit 1
  fi

  if ! command -v "$SHYLL_PATH" > /dev/null; then
    whiptail --msgbox "Error, unable to locate shyll CLI binary.\n\nPath does not exist: \"$SHYLL_PATH\")\n\nGUI will now terminate." $height $width --title "Error"
    exit 1
  fi

  if [ "$EUID" -ne 0 ]; then
    whiptail --msgbox "Shyll detected that you are not running the application as a root user. You must run this application as root to be able to capture ICMP Ping packets.\n\nShyll will now terminate." $height $width --title "Error"
    exit 1
  fi
}

validate_dependencies

read -r -d '' intro_message << INTROEND
Shyll GUI is a small GUI wrapper around the Shyll program which established a covert interactive shell session to enable hidden user interaction with a remote machine.

Please press ENTER to continue.
INTROEND

whiptail --msgbox "$intro_message" $height $width --title "Shyll GUI"

remote_ip=$(whiptail --inputbox "Enter IP Address of Remote Machine to establish connection to" $height $width "127.0.0.1" --title "Connect" 3>&1 1>&2 2>&3)

if [ $? -ne 0 ]; then
  exit 1
fi

session_password=""

while [ -z "$session_password" ]; do
  session_password=$(whiptail --passwordbox "You must specify a password which will be used to authenticate with the remote machine." $height $width "" --title "Password" 3>&1 1>&2 2>&3)

  if [ $? -ne 0 ]; then
    exit 1
  fi
done

"$SCRIPT_DIR/shyll-gui.expect.exp"  "$SHYLL_PATH" "$remote_ip" "$session_password"
