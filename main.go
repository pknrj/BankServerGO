package main

import (
	"fmt"
	"log"
)

func main(){
	 
	store , err := NewPostgresStore()
	if err != nil {
		log.Fatal(err)
	}

	if err := store.InitDb(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("postgres db is connected !!!! ")

	server := NewApiServer(":3000" , store)
	server.Run()

}