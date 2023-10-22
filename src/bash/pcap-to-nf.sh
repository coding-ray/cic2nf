#!/bin/bash
# Usage:
#   ./batch_convert.sh
#
# Description:
#   Scan all files (*.pcap) recursively,
#   and convert them to the corresponding *.nf files
#   or single .nf file.
#
# Prerequisites:
#   APT pacakges: nfdump softflowd

# please enter proper path as follows
# notes:
#   PCAP_IN_DIR       : ensure this directory contains only PCAP files
#   BIN_OUT_DIR       : temporary NetFlow path; all files here will be erased!
#   NF_OUT_DIR        : NetFlow output path
#   TO_MERGE_ALL_PCAP : merge all PCAP files and output a single NetFlow file?
#   MERGED_NF_FILENAME: filename of the merged NetFlow; don't used if not merged
#   PCAP_FILES        : please check this list is properly ordered before converting!
PCAP_IN_DIR=CIC-DDoS-2019/PCAP/PCAP-01-12_0750-0818
BIN_OUT_DIR=nf-binary
NF_OUT_DIR=CIC-DDoS-2019/NetFlow-unlabeled
TO_MERGE_ALL_PCAP="y" # y/n
MERGED_NF_FILENAME="0112_750-818.nf"
# list all files in $PCAP_IN_DIR, and sort by the number after the 2nd '_'
# (split path into columns by '_', and sort by the number in the 3rd column)
PCAP_FILES=$(find $PCAP_IN_DIR -type f | sort -t _ -k 3n)

mkdir -p $BIN_OUT_DIR $NF_OUT_DIR

# input: nothing
# output: nothing
start_netflow_capuring_process() {
  # & to create a detached process
  nfcapd -p 9995 -l $BIN_OUT_DIR >/dev/null &
}

# input $1: PCAP path
# output: nothing
transmit_pcap_as_netflow() {
  pcap_path=$1
  echo -e "\n\n\nPCAP file: $pcap_path"
  softflowd -n "127.0.0.1:9995" -v 5 -r $pcap_path
}

# input $1: pid of NetFlow capturing process
# output: nothing
kill_netflow_capturing_process() {
  process_id=$(pidof nfcapd)
  if [ ! -z "$process_id" ]; then
    kill $process_id
  fi
}

# input $1: file path string
# output in stdout: filename without extension
get_filename() {
  filename=$(basename $1)
  echo "${filename%.*}"
}

# input $1: path to PCAP file
# output: nothing
convert_single_pcap_to_nfcapd() {
  pcap_path_list=$1
  start_netflow_capuring_process
  transmit_pcap_as_netflow $pcap_path_list
  kill_netflow_capturing_process
  sleep 2
}

# input $1: PCAP path list
# output: nothing
convert_multiple_pcap_to_nfcapd() {
  pcap_path_list=$1
  start_netflow_capuring_process
  for pcap_path in $pcap_path_list; do
    transmit_pcap_as_netflow $pcap_path
  done
  kill_netflow_capturing_process
  sleep 2
}

# input $1: path that contains binary NetFlow files (nfcapd.*)
# input $2: path to the output NetFlow file (ooo/xxx.nf)
# output: nothing
convert_nfcapd_to_netflow() {
  input_dir=$1
  output_path=$2
  nfdump -N -o long -R $input_dir >$output_path

  # delete header (1st line), summary, and empty lines
  sed -e "1d" -e "/^[^0-9].*/d" -e "/^ *$/d" -i $output_path

  # sort xxx.nf in place
  sort -n $output_path -o $output_path
}

# input $1: PCAP file list
# output: nothing
independently_convert_pcap_to_netflow() {
  pcap_file_list=$1
  for pcap_path in $pcap_file_list; do
    # xxx.pcap -> nfcapd.*
    echo "1. Convert $pcap_path to $BIN_OUT_DIR/nfcapd.*"
    convert_single_pcap_to_nfcapd $pcap_path

    # nfcapd.* -> xxx.nf
    pcap_filename="$(get_filename $pcap_path)"
    nf_path=$NF_OUT_DIR/$pcap_filename.nf
    echo -e "\n\n\n2. Convert $BIN_OUT_DIR/nfcapd.* to $nf_path"
    convert_nfcapd_to_netflow $BIN_OUT_DIR $nf_path
    rm -f $BIN_OUT_DIR/*

    echo -e "------------------------------------------------------------\n\n\n"
  done
}

# input $1: PCAP file list
# output: nothing
merge_and_convert_pcap_to_netflow() {
  # xxx.pcap -> nfcapd.*
  echo "(Stage 1/2) Convert multiple PCAP files to $BIN_OUT_DIR/nfcapd.*"
  convert_multiple_pcap_to_nfcapd "$1"

  # nfcapd.* -> merged.nf
  nf_path=$NF_OUT_DIR/$MERGED_NF_FILENAME
  echo -e "\n\n\n(Stage 2/2) Convert $BIN_OUT_DIR/nfcapd.* to $nf_path"
  convert_nfcapd_to_netflow $BIN_OUT_DIR $nf_path
  rm -f $BIN_OUT_DIR/*

  echo -e "------------------------------------------------------------\n\n\n"
}

main() {
  if [ "$TO_MERGE_ALL_PCAP" = "y" ]; then
    merge_and_convert_pcap_to_netflow "$PCAP_FILES"
  else
    independently_convert_pcap_to_netflow "$PCAP_FILES"
  fi
  rmdir $BIN_OUT_DIR
}

main
