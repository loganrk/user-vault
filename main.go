package main

import (
	"log"
	"mayilon/config"
	"mayilon/src/router"
	"mayilon/src/store"
)

func main() {
	appConfigIns, err := config.InitApp("")
	if err != nil {
		log.Println(err)

		return
	}

	storeIns, err := store.New(appConfigIns)
	if err != nil {
		log.Println(err)

		return
	}
	err = router.New(appConfigIns, storeIns)
	if err != nil {
		log.Println(err)
	}

	err = storeIns.Close()
	if err != nil {
		log.Println(err)

		return
	}

}
