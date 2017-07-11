package main

import (
	"net/http"
	"flag"
	"log"
)

var (
	port string
	path string
)

func main() {
	flag.StringVar(&port, "port", "8080", "mapping port")
	flag.StringVar(&path, "path", "./", "path for mapping")

	flag.Parse()

	http.Handle("/", http.FileServer(http.Dir(path)))

	log.Fatal(http.ListenAndServe(":" + port, nil))

}
