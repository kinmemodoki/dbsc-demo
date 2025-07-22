package logging

import (
	"log"
	"os"
)

var Logger *log.Logger

func init() {
	Logger = log.New(os.Stdout, "DBSC_DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
}
