# Usage:
#   make [debug]
#
# Desciption:
#   Build the CSV-to-NetFlow binary for part 3.2
#   and the labeling binary for part 3.3. They are
#   csv_to_nf and label_nf, repectively.
#
# Targets:
#   release (Default target) Compile programs with
#           code optimization, without running them.
#   debug   Compile programs with debugging info,
#           and also run the programs.

# add binary extension ".exe" for Windows
# reference: https://gist.github.com/sighingnow/deee806603ec9274fd47
# FIXME: not tested in Linux yet
WIN_EXE_EXT = 
ifeq ($(OS),Windows_NT)
  WIN_EXE_EXT = .exe
endif

release: clean-release
	@cargo build --release
	@cp target/release/csv_to_nf target/release/label_nf .
	@echo "Built binaries: csv_to_nf, label_nf"

debug: clean-debug
	@cargo build --quiet
	@cp target/debug/csv_to_nf$(WIN_EXE_EXT) csv_to_nf-debug$(WIN_EXE_EXT)
	@cp target/debug/label_nf$(WIN_EXE_EXT) label_nf-debug$(WIN_EXE_EXT)
	@echo "Built debugging binaries: csv_to_nf-debug$(WIN_EXE_EXT), \
	label_nf-debug$(WIN_EXE_EXT)"

	./csv_to_nf-debug$(WIN_EXE_EXT) CIC-IDS-2017 BENIGN input/ids/nf-tmp input/ids/CSV/20-records.csv
	./label_nf-debug$(WIN_EXE_EXT)

clean: clean-release clean-debug

clean-release:
	@rm -f csv_to_nf$(WIN_EXE_EXT) label_nf$(WIN_EXE_EXT)

clean-debug:
	@rm -f csv_to_nf-debug$(WIN_EXE_EXT) label_nf-debug$(WIN_EXE_EXT)

clean-cargo:
	@echo "Removed: all previous artifacts of Cargo in target/"
	@cargo clean