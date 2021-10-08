package options

import "flag"

var DBFlag = flag.String("db", "", "filename of the sqlite database")

func init() {
	flag.Parse()
}
