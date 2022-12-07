package common

import (
	"github.com/go-redis/redis/v7"
	"os"
)

var Client *redis.Client

func init() {
	//Initializing redis
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}
	Client = redis.NewClient(&redis.Options{
		Addr:     dsn, //redis port
		Password: "",
		DB:       0,
	})
	_, err := Client.Ping().Result()
	if err != nil {
		panic(err)
	}
}
