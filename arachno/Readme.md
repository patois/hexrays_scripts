
# Arachno for IDA Pro / HexRays

Arachno is an IDAPython script that enhances productivity by semi-automating and simplifying repetitive tasks.

It currently adds the following convenience keyboard shortcuts to IDA/HexRays:

```
---------------------------------------- arachno help ----------------------------------------
Ctrl-Shift-C:	copy current identifier to clipboard
Ctrl-Shift-F:	search the Internet for occurences of the current identifier
Ctrl-Shift-N:	rename function, suggests current identifier as function name
Ctrl-Shift-V:	rename current item, suggests name from clipboard contents
Ctrl-Shift-E:	copy current effective address to clipboard
Ctrl-Shift-H:	print this help
Alt-Left:	jump to previous navigation history location
Alt-Right:	jump to next navigation history location
Ctrl-Alt-Up:	jump to previous function
Ctrl-Alt-Down:	jump to next functionm
```

## Usage

Running the script from within IDA installs a number of keyboard shortcuts by which above functionality is made available.
