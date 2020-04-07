# SharpFinder

Description: Searches for files matching specific criteria on readable shares within the domain.\
Author: Gabriel Ryan ([@s0lst1c3](https://twitter.com/s0lst1c3/))\
Contact: gabriel[aT>specterops.io\
License: GNU v3

## Overview

`SharpFinder` is a C# tool for enumerating files matching specific criteria on readable shares within an Active Directory domain. It is inspired by @harmj0uy's [Find-InterestingFile](https://powersploit.readthedocs.io/en/latest/Recon/Find-InterestingFile/) cmdlet, which is part of [PowerSploit](https://github.com/PowerShellMafia/PowerSploit). 

## General Usage

At it's core, `SharpFinder` works like this:
1. You provide `SharpFinder` with one or more directory paths
2. `SharpFinder` enumerates all readable or writeable files in the provided directories
Generally, you'll want to add filters to make `SharpFinder` to look for specific types of files, but we'll go over that later.

To tell `SharpFinder` to enumerates files within a single directory, use the `--path=` flag as shown in the following example:

```
SharpFinder --path=\\OVERMIND\C$
```

To pass `SharpFinder` a text file containing directories to search through, use the `--input-file=` flag as shown in the example below:

```
SharpFinder --input-file=directory-list.txt
```

## Filtering Results

By default, `SharpFinder` will return all files that it encounters. No keyword, ACL, or extension-based filtering will be performed. The subsections that follow will go over how to tame the output of SharpFinder to yield more precise results.

### Keyword-based Filtering

If you'd like to perform a search for files whose name contains a specific keyword, you can do so using the `--keywords=` flag as shown in the following example:

```
SharpFinder --input-file=directory-list.txt --keywords=credentials
```

You can also specify a list of keywords to the `--keyword=` flag by separating them with a comma, as shown in the next example:

```
SharpFinder --input-file=directory-list.txt --keywords=creds,credential,admin,password
```

### Extension-based Filtering

In addition to keyword-based filtering, SharpShares also allows you to filter for specific file extension using the `--extensions=` flag, as shown in the following example:

```
SharpFinder --input-file=directory-list.txt --extensions=txt
```

As with the keyword-based filter, it is possible to pass a list of file extensions to the `--extensions=` flag, as shown in the following example:

```
SharpFinder --input-file=directory-list.txt --extensions=txt,docx,xlsx
```

### ACL-based filtering

SharpFinder's ACL-based filters allow you to filter for files that you have specific access rights to. To filter for files that we have `read` access to, use the `--readable` flag as shown in the following example:

```
SharpFinder --path=\\OVERMIND\C$ --readable
```

To filter for files that we have `write` access to, use the `--writeable` flag:

```
SharpFinder --path=\\OVERMIND\C$ --writeable
```

To filter for files that we have `read` ___or___ `write` access to, use both the `--readable` and `--writeable` flags:

```
SharpFinder --path=\\OVERMIND\C$ --readable --writeable
```

To filter for files that we have ___both___ `read` and `write` access to, use the `--readable` and `--writeable` flags in conjuction with the `--acl-filter-mode-and` flag:

```
SharpFinder --path=\\OVERMIND\C$ --readable --writeable --acl-filter-mode-and
```

### Excluding Hidden Files

To exclude hidden files from your search, use the `--exclude-hidden` flag as shown below:

```
SharpFinder --path=\\OVERMIND\C$ --exclude-hidden
```

### Combining Filters

All of the filter types that we've gone over can be combined with one another. For example, we can search for all writeable EXE files with the word "update" in their name using the following query:

```
SharpFinder --input-file=readable-shares.txt --exclude-hidden --writeable --keywords=update --extensions=exe
```

In the next example, we search for unattended installation files:

```
SharpFinder --path=C:\ --readable --keywords=unattend,panther --extensions=xml
```

## Grepable Output and CobaltStrike Compatibility

One of the most useful features of SharpFinder is its ability to output results in a format that can be easily extracted from CobaltStrike log files. Say that we want to run SharpFinder using CobaltStrike's `execute-assembly` command. Copying large volumes of output from CobaltStrike can be a pain, so it's preferable if we can just grab it from its log files using `grep`. To do this, first run SharpFinder using the `--grepable` flag as shown in the following example (note: this example uses CobaltStrike's `execute-assembly`):

```
execute-assembly /home/exampleuser/bin/SharpFinder --grepable --path=C:\ --readable --writeable --keywords=admin,creds,credentials --extensions=kbdx,xlsx,doc,docx,txt,ps1,bat
```

You could then extract the results of your query from CobaltStrike's logs by running the following command in your CobaltStrike log directory:

```
grep -r SharpFinder .
```
