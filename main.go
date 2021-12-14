package main

import (
	"archive/zip"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// org/apache/logging/log4j/core/net/JndiManager.class
// org/apache/logging/log4j/core/lookup/JndiLookup.class

var (
	Build     = "xxxx"
	GitCommit = "unknown"
	GitBranch = "unknown"
	BuildTime = "unknown"
	Name      = "check-log4shell"
)

type PathList []string
type HashList []string

func (v *PathList) Set(val string) error {
	*v = append(*v, val)
	return nil
}

func (v *PathList) String() string {
	return "nhec"
}

func (v *HashList) Set(val string) error {
	*v = append(*v, val)
	return nil
}

func (v *HashList) String() string {
	return "nhec"
}

type Match struct {
	JarPath   string
	ClassPath string
	CRC32     string
}

type Vulnerable struct {
	CRC32     string
	JarName   string
	Version   string
	ClassPath string
}

var pathList PathList
var alertOnFail bool
var verbose bool
var jarName = `(?i)^.*\.(jar|ear|war|zip)$`

func main() {

	InitList()

	flag.Var(&pathList, "path", "path to scan (can be used multiple times)")
	flag.StringVar(&jarName, "name", jarName, "jar name regex")
	flag.BoolVar(&alertOnFail, "alertOnFail", true, "alert if there's an error hashing")
	flag.BoolVar(&verbose, "verbose", false, "verbose")
	flag.Parse()

	if verbose {
		built := BuildTime
		i, err := strconv.ParseInt(BuildTime, 10, 64)
		if err == nil {
			t := time.Unix(i, 0)
			built = t.Format(time.RFC3339)
		}
		fmt.Printf("%s build=%s (git=%s branch=%s) (built %s) using %s\n",
			Name, Build, GitCommit, GitBranch, built, runtime.Version())
	}

	if len(pathList) == 0 {
		if runtime.GOOS == "linux" {
			pathList = []string{`/`}
		}
		if runtime.GOOS == "windows" {
			pathList = []string{`C:\`}
		}
		if verbose {
			log.Printf("INF: using default path list %v", pathList)
		}
	}

	for _, thePath := range pathList {
		if verbose {
			log.Printf("INF: doing %s", thePath)
		}
		list := Walking(thePath)
		for _, v := range list {
			fmt.Printf("class %s (%s) in file %s is vulnerable to Log4Shell. (from log4j ver=%s)\n",
				v.ClassPath,
				v.CRC32,
				v.JarPath,
				vulnList[v.CRC32].Version,
			)
		}
		if len(list) > 0 {
			fmt.Printf("CRITICAL: %d classes are vulnerable to Log4Shell (CVE-2021-44228).\n", len(list))
			os.Exit(2)
		}
	}
	fmt.Println("OK: no Log4Shell vulnerability found.")
	os.Exit(0)
}

func getHash(name string) (string, error) {
	file, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := md5.New()
	_, err = io.Copy(hash, file)

	if err != nil {
		return "", err
	}
	return string(hex.EncodeToString(hash.Sum(nil))), nil
}

func Walking(p string) []Match {

	var list []Match

	libRegEx, e := regexp.Compile(jarName)
	if e != nil {
		log.Fatal(e)
	}

	e = filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
		if err == nil && libRegEx.MatchString(info.Name()) {
			m, bad := checkInJar(path)
			if bad != nil {
				if verbose {
					log.Printf("ERR: %s failed with %v", path, bad)
				}
				//return bad
			}
			if len(m) > 0 {
				list = append(list, m...)
			}
		}
		return nil
	})
	if e != nil {
		if verbose {
			log.Printf("ERR: %s failed with %v", p, e)
		}
	}
	return list
}

func checkInJar(p string) ([]Match, error) {

	list := []Match{}

	if verbose {
		log.Printf("INF: checking %s", p)
	}

	read, err := zip.OpenReader(p)
	if err != nil {
		return nil, err
	}
	defer read.Close()

	for _, file := range read.File {
		crc := strconv.FormatUint(uint64(file.CRC32), 16)
		if _, ok := vulnList[crc]; ok {
			list = append(list, Match{
				JarPath:   p,
				ClassPath: file.Name,
				CRC32:     crc,
			})
		}
	}
	return list, nil
}

var vulnList = map[string]Vulnerable{}

func InitList() {
	for _, line := range ClassList {
		fields := strings.Fields(line)
		vulnList[fields[2]] = Vulnerable{
			CRC32:     fields[2],
			JarName:   fields[0],
			Version:   fields[1],
			ClassPath: fields[3],
		}
	}
}

// --------------crc.go-appended----------

var ClassList = []string{
	`log4j-core-2.0.1.jar 2.0.1 a4216188 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.0.2.jar 2.0.2 2fe1b23e org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.0-beta9.jar 2.0-beta9 b76a611c org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.0.jar 2.0 4745c8b2 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.0-rc1.jar 2.0-rc1 b76a611c org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.0-rc2.jar 2.0-rc2 61ed2486 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.10.0.jar 2.10.0 4b8d2ae5 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.10.0.jar 2.10.0 9393311a org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.11.0.jar 2.11.0 4b8d2ae5 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.11.0.jar 2.11.0 9393311a org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.11.1.jar 2.11.1 4b8d2ae5 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.11.1.jar 2.11.1 9393311a org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.11.2.jar 2.11.2 4b8d2ae5 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.11.2.jar 2.11.2 9393311a org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.12.0.jar 2.12.0 abff513e org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.12.0.jar 2.12.0 82e2179e org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.12.1.jar 2.12.1 abff513e org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.12.1.jar 2.12.1 82e2179e org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.13.0.jar 2.13.0 956e09da org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.13.0.jar 2.13.0 b546dadf org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.13.1.jar 2.13.1 956e09da org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.13.1.jar 2.13.1 b546dadf org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.13.2.jar 2.13.2 956e09da org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.13.2.jar 2.13.2 b546dadf org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.13.3.jar 2.13.3 956e09da org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.13.3.jar 2.13.3 b546dadf org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.14.0.jar 2.14.0 29da1d9c org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.14.1.jar 2.14.1 29da1d9c org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.1.jar 2.1 17a0cd9f org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.1.jar 2.1 a01792f8 org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.2.jar 2.2 17a0cd9f org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.2.jar 2.2 a01792f8 org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.3.jar 2.3 17a0cd9f org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.3.jar 2.3 a01792f8 org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.4.1.jar 2.4.1 55915383 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.4.1.jar 2.4.1 a13c5fd1 org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.4.jar 2.4 55915383 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.4.jar 2.4 a13c5fd1 org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.5.jar 2.5 55915383 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.5.jar 2.5 a13c5fd1 org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.6.1.jar 2.6.1 46306152 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.6.1.jar 2.6.1 47ba9c27 org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.6.2.jar 2.6.2 46306152 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.6.2.jar 2.6.2 47ba9c27 org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.6.jar 2.6 46306152 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.6.jar 2.6 47ba9c27 org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.7.jar 2.7 d54c7ffd org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.7.jar 2.7 c79cdfe1 org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.8.1.jar 2.8.1 080c8f77 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.8.1.jar 2.8.1 c79cdfe1 org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.8.2.jar 2.8.2 948e2ee9 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.8.2.jar 2.8.2 e1e8d0ca org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.8.jar 2.8 080c8f77 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.8.jar 2.8 c79cdfe1 org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.9.0.jar 2.9.0 4b8d2ae5 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.9.0.jar 2.9.0 9393311a org/apache/logging/log4j/core/net/JndiManager.class`,
	`log4j-core-2.9.1.jar 2.9.1 4b8d2ae5 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
	`log4j-core-2.9.1.jar 2.9.1 9393311a org/apache/logging/log4j/core/net/JndiManager.class`,
}

//`log4j-core-2.14.1.jar 2.14.1 23a35f29 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
//`log4j-core-2.14.0.jar 2.14.0 23a35f29 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
//`log4j-core-2.15.0.jar 2.15.0 23a35f29 org/apache/logging/log4j/core/lookup/JndiLookup.class`,
//`log4j-core-2.15.0.jar 2.15.0 dc81b765 org/apache/logging/log4j/core/net/JndiManager.class`,
