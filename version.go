package main

import "strconv"

const versionMajor = 0
const versionMinor = 1
const versionBugfix = 0
const versionGit = true

// Returns the current version as string in the form major.minor.bugfix(-git)
func getVersion() string {
	if versionGit {
		return strconv.Itoa(versionMajor) + "." + strconv.Itoa(versionMinor) + "." + strconv.Itoa(versionBugfix) + "-git"
	} else {
		return strconv.Itoa(versionMajor) + "." + strconv.Itoa(versionMinor) + "." + strconv.Itoa(versionBugfix)
	}
}
